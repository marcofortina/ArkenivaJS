// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { fixture, send, settings } from '../http-fixture.js';

function ambiguousRequest(origin: string, path: string, first: string, second: string) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const outgoing = request(
      origin + path,
      {
        headers: [
          'Host',
          new URL(origin).host,
          'Authorization',
          first,
          'aUtHoRiZaTiOn',
          second,
          'Connection',
          'close',
        ],
      },
      (response) => {
        const chunks: Buffer[] = [];
        let bytes = 0;
        response.on('data', (chunk: Buffer) => {
          bytes += chunk.length;
          if (bytes > 16384)
            outgoing.destroy(new Error('The bounded ambiguity response was exceeded'));
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('end', () =>
          resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString() }),
        );
      },
    );
    outgoing.once('error', reject);
    outgoing.end();
  });
}

for (const surface of ['dispatch', 'capabilities'] as const)
  test(
    `Real HTTP ${surface} rejects duplicate bearer headers without selecting the first or last tenant`,
    { timeout: 10000 },
    async () => {
      const base = settings();
      let authorizations = 0,
        effects = 0;
      const f = await fixture({
        ...base,
        authorize() {
          authorizations++;
          return true;
        },
        handlers: Object.fromEntries(
          Object.entries(base.handlers).map(([name, handler]) => [
            name,
            (context: Parameters<typeof handler>[0]) => {
              effects++;
              return handler(context);
            },
          ]),
        ),
      });
      try {
        const north = await f.token('north'),
          south = await f.token('south'),
          path = surface === 'dispatch' ? '/api/orders/id' : '/api/tenant/capabilities';
        for (const [first, second] of [
          [north, north],
          [north, south],
          [south, north],
        ] as const) {
          const denied = await ambiguousRequest(f.origin, path, first, second);
          assert.equal(denied.status, 401, denied.body);
          assert.equal(
            (JSON.parse(denied.body) as { error: { code: string } }).error.code,
            'EK_AUTH_REQUIRED',
          );
          assert.equal(authorizations, 0, 'Ambiguous authority must fail before operation policy');
          assert.equal(effects, 0, 'No first-header or last-header tenant may invoke a handler');
          assert.doesNotMatch(denied.body + f.logs(), /Bearer |synthetic-operator/);
        }
        const healthy = await send(f.origin, path, { headers: { authorization: north } });
        assert.equal(healthy.status, 200, healthy.body);
        if (surface === 'dispatch') {
          assert.equal(healthy.json().tenant, 'north');
          assert.equal(effects, 1);
          assert.equal(authorizations, 1);
        } else {
          assert.equal((healthy.json().capabilities as unknown[]).length, 2);
          assert.equal(effects, 0);
          assert.equal(authorizations, 2);
        }
      } finally {
        await f.close();
      }
    },
  );
