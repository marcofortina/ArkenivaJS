// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';

/** Only this owned loopback fixture can change its dependency readiness. */
export async function startHealthFixture() {
  const marker = 'owned-health-probe-value';
  const state = { ready: true, probes: 0, failedProbes: 0, changes: 0 };
  const server = createServer((request, response) => {
    void (async () => {
      assert.equal(request.headers['x-health-fixture'], marker);
      response.setHeader('cache-control', 'no-store');
      if (request.method === 'GET' && request.url === '/probe') {
        state.probes++;
        if (!state.ready) state.failedProbes++;
        response.writeHead(state.ready ? 200 : 503).end(marker);
        return;
      }
      assert.equal(request.method, 'POST');
      assert.equal(request.url, '/control');
      let body = '';
      for await (const chunk of request) {
        body += chunk.toString('utf8');
        assert.ok(Buffer.byteLength(body) <= 64);
      }
      const change = JSON.parse(body);
      assert.deepEqual(Object.keys(change), ['ready']);
      assert.equal(typeof change.ready, 'boolean');
      state.ready = change.ready;
      state.changes++;
      response.writeHead(204).end();
    })().catch(() => {
      response.writeHead(500).end();
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  return {
    fixture: { origin: 'http://127.0.0.1:' + address.port, marker },
    state,
    async close() {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}
