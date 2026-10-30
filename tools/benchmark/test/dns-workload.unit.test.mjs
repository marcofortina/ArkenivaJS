// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import dns from 'node:dns/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDnsService } from '@arkenivajs/dns';
import { startDnsFixture } from '../../../examples/dns/dist/fixture.js';
import { nativeDns, dnsSettings, verifyDns } from '../dns-workload.mjs';

test('Native and public DNS execute all eleven actual record families, OS lookup and PTR without global resolver changes', async () => {
  const before = dns.getServers(),
    authority = await startDnsFixture(),
    fixture = { server: authority.server, hostname: 'internal.test' };
  try {
    for (const client of [nativeDns(fixture), createDnsService(dnsSettings(fixture))]) {
      try {
        assert.equal((await verifyDns(client, fixture)).checkedRecordFamilies, 11);
      } finally {
        await client.close();
      }
    }
    assert.equal(authority.requests, 24);
    assert.deepEqual(dns.getServers(), before);
  } finally {
    await authority.close();
  }
});

test(
  'DNS diagnostic comparison awaits native wire responses and retains no query or server input in reports',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-dns-harness-')),
      script = fileURLToPath(new URL('../dns.mjs', import.meta.url));
    try {
      for (const mode of ['--verify', '--smoke']) {
        const output = join(directory, mode.slice(2));
        await promisify(execFile)(process.execPath, [script, mode, output], {
          timeout: 25000,
          maxBuffer: 1048576,
        });
        const report = JSON.parse(await readFile(join(output, 'report.json'), 'utf8')),
          wire = JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8'));
        assert.equal(report.measured, mode === '--smoke');
        assert.equal(report.releaseGate, false);
        assert.equal(report.records.length, 4);
        assert.equal(report.collector.inputOccurrences, 0);
        assert.ok(report.collector.receivedBodies >= 2);
        assert.equal(wire.globalResolversUnchanged, true);
        assert.equal(wire.forwardedRequests, 0);
        assert.ok(wire.receivedDnsRequests >= (mode === '--smoke' ? 4800 : 48));
        for (const row of report.records) {
          assert.equal(row.verification.checkedRecordFamilies, 11);
          assert.equal(row.verification.globalResolversUnchanged, true);
          assert.equal(row.records.length, mode === '--smoke' ? 14 : 0);
          for (const operation of row.records) {
            assert.ok(operation.sampleCount >= 100);
            for (const value of Object.values(operation.latencyNanoseconds))
              assert.ok(Number.isFinite(value) && value >= 0);
          }
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
