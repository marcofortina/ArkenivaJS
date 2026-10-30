// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { request as httpRequest } from 'node:http';
import type { ClientRequest } from 'node:http';
import { readFile } from 'node:fs/promises';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { within } from '@arkenivajs/core/support';
import type { TenantRegistrySnapshotV1_1 } from '../../dist/index.js';
import { registryContentChecksum } from '../../dist/registry.js';
import { fixture, registry, send, settings, tlsFiles } from '../http-fixture.js';

async function approvedUpstream() {
  const material = await tlsFiles(),
    requests: { path: string; body: unknown }[] = [],
    tasks = new Set<Promise<void>>();
  let connections = 0;
  const server = createServer(
    {
      key: await readFile(material.tls.privateKeyFile),
      cert: await readFile(material.tls.certificateFile),
    },
    (request, response) => {
      const task = (async () => {
        const parts: Buffer[] = [];
        let bytes = 0;
        for await (const chunk of request) {
          const value = Buffer.from(chunk as Uint8Array);
          bytes += value.length;
          assert.ok(bytes <= 4096);
          parts.push(value);
        }
        assert.equal(request.method, 'POST');
        assert.equal(request.url, '/fixed');
        assert.equal(request.headers.authorization, undefined);
        const body = JSON.parse(Buffer.concat(parts).toString()) as { ref: string };
        requests.push({ path: request.url, body });
        response
          .writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ reference: 'partner-' + body.ref }));
      })()
        .catch(() => {
          response.writeHead(500).end();
        })
        .finally(() => tasks.delete(task));
      tasks.add(task);
    },
  );
  server.on('connection', () => {
    connections++;
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    return {
      origin: 'https://127.0.0.1:' + address.port,
      caFile: material.tls.certificateFile,
      requests,
      connections: () => connections,
      async close() {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server.close(() => resolve()));
        await Promise.allSettled([...tasks]);
        await material.close();
      },
    };
  } catch (error) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await material.close();
    throw error;
  }
}

for (const [transformation, cancellation] of [
  ['request', 'deadline'],
  ['request', 'client-disconnect'],
  ['response', 'deadline'],
  ['response', 'client-disconnect'],
] as const)
  test(
    `A real ${cancellation} retains an uncooperative ${transformation} transformer without late upstream effects or queued execution`,
    { timeout: 10000 },
    async () => {
      const target = await approvedUpstream();
      let f: Awaited<ReturnType<typeof fixture>> | undefined,
        outgoing: ClientRequest | undefined,
        pending: ReturnType<typeof send> | undefined,
        signal: AbortSignal | undefined,
        calls = 0,
        enter!: () => void,
        release!: () => void,
        cancelled!: () => void,
        exited!: () => void;
      const entered = new Promise<void>((resolve) => {
          enter = resolve;
        }),
        gate = new Promise<void>((resolve) => {
          release = resolve;
        }),
        aborted = new Promise<void>((resolve) => {
          cancelled = resolve;
        }),
        physicalExit = new Promise<void>((resolve) => {
          exited = resolve;
        });
      try {
        const original = registry(),
          content = {
            ...original,
            operations: original.operations.map((operation) =>
              operation.id === 'orders.read'
                ? {
                    ...operation,
                    maxConcurrency: 1,
                    timeoutMs: cancellation === 'deadline' ? 500 : 5000,
                  }
                : operation,
            ),
            implementations: [
              original.implementations[0]!,
              {
                id: 'south-orders',
                kind: 'http' as const,
                upstreamKey: 'partner',
                upstreamPath: '/fixed',
                method: 'POST' as const,
                requestTransformerKey: 'partner-input',
                responseTransformerKey: 'partner-output',
              },
            ],
          },
          snapshot: TenantRegistrySnapshotV1_1 = {
            ...content,
            contentChecksum: registryContentChecksum(content),
          };
        f = await fixture({
          ...settings(snapshot),
          approvedUpstreams: [
            {
              key: 'partner',
              origin: target.origin,
              allowedHostnames: ['127.0.0.1'],
              allowedCidrs: ['127.0.0.1/32'],
              tlsCaFile: target.caFile,
              connectionTimeoutMs: 1000,
              allowRedirects: false,
            },
          ],
          requestTransformers: {
            async 'partner-input'(_payload, context) {
              if (transformation === 'request') {
                calls++;
                if (calls === 1) {
                  signal = context.signal;
                  signal.addEventListener('abort', cancelled, { once: true });
                  enter();
                  // Trusted application work may ignore cancellation; the caller still owns it.
                  await gate;
                  exited();
                }
              }
              return { ref: context.params.id };
            },
          },
          responseTransformers: {
            async 'partner-output'(payload, context) {
              if (transformation === 'response') {
                calls++;
                if (calls === 1) {
                  signal = context.signal;
                  signal.addEventListener('abort', cancelled, { once: true });
                  enter();
                  // Partner work has completed, but this transformation still owns its permit.
                  await gate;
                  exited();
                }
              }
              return {
                tenant: context.auth!.tenantId,
                implementation: 'partner',
                id: (payload as { reference: string }).reference,
              };
            },
          },
        });
        const authorization = await f.token('south');
        if (cancellation === 'deadline')
          pending = send(f.origin, '/api/orders/cancelled', { headers: { authorization } });
        else {
          outgoing = httpRequest(f.origin + '/api/orders/cancelled', {
            headers: { authorization },
          });
          outgoing.on('error', () => {});
          outgoing.end();
        }
        await within(() => entered, { timeoutMs: 2000 });
        if (outgoing) outgoing.destroy();
        if (pending) {
          const expired = await pending;
          assert.equal(expired.status, 504, expired.body);
          assert.doesNotMatch(expired.body, /partner-input|127\.0\.0\.1/);
        }
        await within(() => aborted, { timeoutMs: 2000 });
        assert.equal(signal?.aborted, true);
        const blocked = await send(f.origin, '/api/orders/blocked', {
          headers: { authorization },
        });
        assert.equal(blocked.status, 503, blocked.body);
        assert.equal((blocked.json().error as { code: string }).code, 'EK_TROUTE_CAPACITY');
        assert.equal(calls, 1, 'Saturation must not queue or re-enter the physical transformer');
        const healthy = await send(f.origin, '/api/orders', {
          method: 'POST',
          body: { id: 'healthy' },
          headers: { authorization: await f.token('north') },
        });
        assert.equal(healthy.status, 200, healthy.body);
        assert.equal(healthy.json().tenant, 'north');
        const initialRequests =
          transformation === 'request' ? [] : [{ path: '/fixed', body: { ref: 'cancelled' } }];
        assert.equal(target.connections(), transformation === 'request' ? 0 : 1);
        assert.deepEqual(target.requests, initialRequests);
        const initialConnections = target.connections();
        release();
        await within(() => physicalExit, { timeoutMs: 2000 });
        await nextTurn();
        assert.equal(calls, 1, 'Rejected requests must never execute after capacity returns');
        assert.equal(
          target.connections(),
          initialConnections,
          'Late transformation cannot open an upstream socket',
        );
        assert.deepEqual(
          target.requests,
          initialRequests,
          'Late transformation cannot send or replay an upstream request',
        );
        const recovered = await send(f.origin, '/api/orders/recovered', {
          headers: { authorization },
        });
        assert.equal(recovered.status, 200, recovered.body);
        assert.equal(recovered.json().id, 'partner-recovered');
        assert.equal(calls, 2);
        assert.ok(target.connections() >= 1 && target.connections() <= 2);
        assert.deepEqual(target.requests, [
          ...initialRequests,
          { path: '/fixed', body: { ref: 'recovered' } },
        ]);
        assert.doesNotMatch(f.logs(), /Bearer /);
      } finally {
        outgoing?.destroy();
        release();
        await pending?.catch(() => undefined);
        try {
          await f?.close();
        } finally {
          await target.close();
        }
      }
    },
  );
