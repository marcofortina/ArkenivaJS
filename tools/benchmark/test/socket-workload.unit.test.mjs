// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:net';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { exchangeSocket } from '../socket-client.mjs';
import { socketClient } from '../socket-workload.mjs';

test('Socket client rejects unowned destinations and invalid bounds before opening sockets', async () => {
  const input = {
    kind: 'tcp',
    size: 64,
    marker: 'owned-test',
    binding: { network: { address: 'foreign.invalid', port: 1 } },
  };
  await assert.rejects(exchangeSocket(input));
  await assert.rejects(exchangeSocket({ ...input, size: 1 }));
  await assert.rejects(
    exchangeSocket({ ...input, kind: 'unix', binding: { path: '/foreign/socket' } }),
  );
  await assert.rejects(exchangeSocket({ ...input, marker: '' }));
});

test(
  'Independent socket client rejects corrupted bytes from an actual owned TCP server',
  { timeout: 10000 },
  async () => {
    const peers = new Set();
    const server = createServer((peer) => {
      peers.add(peer);
      peer.once('close', () => peers.delete(peer));
      peer.once('data', () => peer.end(Buffer.alloc(64)));
    });
    await new Promise((done, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', done);
    });
    try {
      await assert.rejects(
        socketClient({
          kind: 'tcp',
          size: 64,
          marker: 'owned-corruption-control',
          binding: { network: server.address() },
        }),
      );
    } finally {
      for (const peer of peers) peer.destroy();
      await new Promise((done) => server.close(done));
    }
  },
);

test(
  'Four socket profiles verify five native transport scenarios with independent client processes',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-harness-'));
    const script = fileURLToPath(new URL('../socket.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8');
      const report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.doesNotMatch(encoded, /arkenivajs-socket-comparison-|127\.0\.0\.1|localhost/);
      for (const row of report.records) {
        assert.equal(row.verification.independentClientProcess, true);
        assert.equal(row.verification.tlsWrongNameRejected, true);
        assert.equal(row.verification.unixPathRemoved, true);
        assert.equal(row.verification.scenarios.length, 5);
        assert.deepEqual(
          row.verification.scenarios.map(({ kind, payloadBytes }) => [kind, payloadBytes]),
          [
            ['tcp', 64],
            ['tcp', 65536],
            ['tls', 64],
            ['udp', 256],
            ['unix', 4096],
          ],
        );
        for (const scenario of row.verification.scenarios) {
          assert.equal(scenario.receivedBytes, scenario.payloadBytes);
          assert.equal(scenario.byteIdentityVerified, true);
          assert.equal(scenario.serverBytesVerified, true);
          assert.equal(scenario.closed, true);
          if (scenario.kind === 'tls') {
            assert.match(scenario.tls.protocol, /^TLSv1\.[23]$/);
            assert.equal(typeof scenario.tls.cipher, 'string');
          }
        }
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      const unsupported = join(directory, 'unsupported');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', unsupported], { timeout: 5000 }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
