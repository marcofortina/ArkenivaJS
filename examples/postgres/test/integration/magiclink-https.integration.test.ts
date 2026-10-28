// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:https';
import { createServer } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApplication, COMPONENTS } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { apiPlugin } from '@arkenivajs/api';
import { magicLinkConfirmationPlugin } from '../../dist/magiclink-confirmation.js';
import { magicLinkFixture } from './magiclink-fixture.js';

test(
  'Actual HTTPS scanner prefetch never consumes; explicit same-origin POST confirms once without URL leakage',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-magiclink-https-'));
    let fixture: Awaited<ReturnType<typeof magicLinkFixture>> | undefined;
    let app: Awaited<ReturnType<typeof createApplication>> | undefined;
    try {
      const certificateFile = join(directory, 'server.pem'),
        privateKeyFile = join(directory, 'server.key');
      await promisify(execFile)(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'ec',
          '-pkeyopt',
          'ec_paramgen_curve:P-256',
          '-nodes',
          '-days',
          '1',
          '-subj',
          '/CN=localhost',
          '-addext',
          'subjectAltName=DNS:localhost,IP:127.0.0.1',
          '-keyout',
          privateKeyFile,
          '-out',
          certificateFile,
        ],
        { timeout: 10000 },
      );
      await chmod(privateKeyFile, 0o600);
      await chmod(certificateFile, 0o400);
      const reservation = createServer();
      await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
      const address = reservation.address();
      assert.ok(address && typeof address === 'object');
      const port = address.port;
      await new Promise<void>((resolve) => reservation.close(() => resolve()));
      const origin = 'https://127.0.0.1:' + port,
        urls: string[] = [],
        ca = await readFile(certificateFile);
      fixture = await magicLinkFixture(8, 60000, origin + '/confirm');
      app = await createApplication({
        service: { name: 'magiclink-confirmation', version: '1.0.0', environment: 'test' },
        logging: { level: 'silent' },
        http: {
          protocol: 'https',
          host: '127.0.0.1',
          port,
          tls: { certificateFile, privateKeyFile },
        },
        plugins: [
          loggingPlugin(),
          apiPlugin(),
          magicLinkConfirmationPlugin(fixture.first.magic, origin),
          {
            id: 'request-observation',
            version: '1.0.0',
            capabilities: new Set(),
            dependencies: ['api'],
            init(context) {
              const server = context
                .require<import('@arkenivajs/core').ApiServer>(COMPONENTS.api)
                .native() as import('fastify').FastifyInstance;
              server.addHook('onRequest', async (request) => {
                urls.push(request.raw.url ?? '');
              });
            },
            close() {},
          },
        ],
      });
      await app.start();
      const exchange = (path: string, method = 'GET', body?: unknown, requestOrigin = origin) =>
        new Promise<{
          status: number;
          headers: import('node:http').IncomingHttpHeaders;
          body: string;
        }>((resolve, reject) => {
          const encoded = body === undefined ? undefined : JSON.stringify(body),
            outgoing = request(
              new URL(path, origin),
              {
                ca,
                rejectUnauthorized: true,
                method,
                headers: {
                  ...(encoded
                    ? {
                        'content-type': 'application/json',
                        'content-length': Buffer.byteLength(encoded),
                      }
                    : {}),
                  origin: requestOrigin,
                },
              },
              (response) => {
                const chunks: Buffer[] = [];
                response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
                response.once('end', () =>
                  resolve({
                    status: response.statusCode!,
                    headers: response.headers,
                    body: Buffer.concat(chunks).toString('utf8'),
                  }),
                );
              },
            );
          outgoing.once('error', reject);
          if (encoded) outgoing.write(encoded);
          outgoing.end();
        });
      const activeFixture = fixture;
      const account = await activeFixture.session(),
        issued = await account.run(() => activeFixture.first.magic.issue(account.subject, 'login'));
      const confirmation = new URL(issued.redemptionUrl);
      const prefetched = await exchange(confirmation.href);
      assert.equal(prefetched.status, 200);
      assert.equal(prefetched.headers['referrer-policy'], 'no-referrer');
      assert.equal(prefetched.headers['cache-control'], 'no-store');
      assert.ok(prefetched.body.includes('method="post"'));
      assert.ok(!prefetched.body.includes(issued.value));
      assert.ok(urls.every((url) => !url.includes(issued.value) && !url.includes('#')));
      const script = await exchange('/magiclink-confirmation.js');
      assert.ok(script.body.includes('history.replaceState'));
      assert.ok(script.body.includes("method: 'POST'"));
      const foreign = await exchange(
        '/magic/consume',
        'POST',
        { token: issued.value, purpose: 'login' },
        'https://foreign.example',
      );
      assert.equal(foreign.status, 400);
      const confirmed = await exchange('/magic/consume', 'POST', {
        token: issued.value,
        purpose: 'login',
      });
      assert.equal(confirmed.status, 200);
      assert.deepEqual(JSON.parse(confirmed.body), { confirmed: true });
      const reused = await exchange('/magic/consume', 'POST', {
        token: issued.value,
        purpose: 'login',
      });
      assert.equal(reused.status, 400);
      assert.deepEqual(JSON.parse(reused.body), { confirmed: false });
      assert.equal(reused.headers['referrer-policy'], 'no-referrer');
      await assert.rejects(
        fixture.second.magic.consume(issued.value, { method: 'POST', purpose: 'login' }),
        { code: 'EK_MAGICLINK_REPLAY' },
      );
    } finally {
      try {
        await app?.stop();
      } finally {
        await fixture?.close();
        await rm(directory, { recursive: true, force: true });
      }
    }
  },
);
