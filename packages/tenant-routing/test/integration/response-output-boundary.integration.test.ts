// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { registryContentChecksum } from '../../dist/registry.js';
import { fixture, registry, send, settings, tlsFiles } from '../http-fixture.js';

test(
  'A valid HTTPS partner response cannot bypass the final transformed-output byte and inert-data boundary',
  { timeout: 10000 },
  async () => {
    const material = await tlsFiles();
    let server: ReturnType<typeof createServer> | undefined,
      f: Awaited<ReturnType<typeof fixture>> | undefined,
      requests = 0,
      transformations = 0,
      traps = 0,
      output: unknown;
    try {
      server = createServer(
        {
          key: await readFile(material.tls.privateKeyFile),
          cert: await readFile(material.tls.certificateFile),
        },
        (request, response) => {
          requests++;
          assert.equal(request.url, '/fixed');
          assert.equal(request.headers.authorization, undefined);
          response
            .writeHead(200, { 'content-type': 'application/json' })
            .end('{"reference":"private-partner-payload"}');
        },
      );
      await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      assert.ok(address && typeof address === 'object');
      const original = registry(),
        content = {
          ...original,
          implementations: [
            original.implementations[0]!,
            {
              id: 'south-orders',
              kind: 'http' as const,
              upstreamKey: 'partner',
              upstreamPath: '/fixed',
              method: 'GET' as const,
              responseTransformerKey: 'partner-output',
            },
          ],
        };
      f = await fixture({
        ...settings({ ...content, contentChecksum: registryContentChecksum(content) }),
        approvedUpstreams: [
          {
            key: 'partner',
            origin: 'https://127.0.0.1:' + address.port,
            allowedHostnames: ['127.0.0.1'],
            allowedCidrs: ['127.0.0.1/32'],
            tlsCaFile: material.tls.certificateFile,
            connectionTimeoutMs: 1000,
            allowRedirects: false,
          },
        ],
        responseTransformers: {
          'partner-output': (payload) => {
            transformations++;
            assert.deepEqual(payload, { reference: 'private-partner-payload' });
            return output;
          },
        },
      });
      const valid = { tenant: 'south', implementation: 'partner', id: 'recovered' },
        accessor = Object.defineProperty({ ...valid }, 'id', {
          enumerable: true,
          get() {
            traps++;
            return 'private-transformed-output';
          },
        }),
        proxy = new Proxy(
          { ...valid },
          {
            getPrototypeOf() {
              traps++;
              throw new Error('Private transformed-output proxy trap');
            },
            ownKeys() {
              traps++;
              throw new Error('Private transformed-output proxy trap');
            },
            getOwnPropertyDescriptor() {
              traps++;
              throw new Error('Private transformed-output proxy trap');
            },
          },
        ),
        authorization = await f.token('south');
      for (output of [
        accessor,
        proxy,
        { ...valid, id: 'private-transformed-output:' + '\u0000'.repeat(1000) },
      ]) {
        const denied = await send(f.origin, '/api/orders/id', { headers: { authorization } });
        assert.equal(denied.status, 502, denied.body);
        assert.equal((denied.json().error as { code: string }).code, 'EK_TROUTE_CONTRACT');
        assert.equal(
          traps,
          0,
          'Response data inspection must never invoke application accessors or proxy traps',
        );
        assert.equal(
          requests,
          transformations,
          'A response contract failure cannot replay partner work',
        );
        assert.doesNotMatch(
          denied.body + f.logs(),
          /private-partner-payload|private-transformed-output|Private transformed-output proxy trap|Bearer |127\.0\.0\.1/,
        );
      }
      output = valid;
      const recovered = await send(f.origin, '/api/orders/id', { headers: { authorization } });
      assert.equal(recovered.status, 200, recovered.body);
      assert.deepEqual(recovered.json(), valid);
      assert.equal(requests, 4);
      assert.equal(transformations, 4);
      assert.equal(traps, 0);
    } finally {
      try {
        await f?.close();
      } finally {
        if (server?.listening) {
          server.closeAllConnections();
          await new Promise<void>((resolve) => server!.close(() => resolve()));
        }
        await material.close();
      }
    }
  },
);
