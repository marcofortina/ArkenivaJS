// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { routingCoordinates } from '../routing-workload.mjs';

test('Routing comparison rejects foreign issuers, ambiguous trust files and duplicate tenant coordinates before I/O', () => {
  const valid = {
    issuer: 'http://127.0.0.1:1',
    privateKeyFile: '/owned/key',
    certificateFile: '/owned/cert',
    ca: 'owned-certificate',
    tenant: 'north',
    otherTenant: 'south',
    emptyTenant: 'empty',
  };
  routingCoordinates(valid);
  for (const issuer of [
    'https://127.0.0.1:1',
    'http://foreign.invalid:1',
    'http://u:p@127.0.0.1:1',
    'http://127.0.0.1:1/keys',
    'http://127.0.0.1:1?redirect=1',
  ])
    assert.throws(() => routingCoordinates({ ...valid, issuer }));
  for (const privateKeyFile of ['relative.key', '/owned/key\n', '/owned/key\0'])
    assert.throws(() => routingCoordinates({ ...valid, privateKeyFile }));
  for (const otherTenant of [valid.tenant, null, 'tenant\n', 'x'.repeat(65)])
    assert.throws(() => routingCoordinates({ ...valid, otherTenant }));
});

test('Routing verification refuses unsupported sampling before creating evidence', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-routing-mode-'));
  try {
    const output = join(directory, 'sampling');
    await assert.rejects(
      promisify(execFile)(process.execPath, [
        fileURLToPath(new URL('../routing.mjs', import.meta.url)),
        '--smoke',
        output,
      ]),
      (error) => /Use --verify/.test(error.stderr),
    );
    await assert.rejects(stat(output), { code: 'ENOENT' });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test(
  'Four actual HTTPS routing profiles retain tenant dispatch, denied effects, private bounded discovery and parented usage',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-routing-harness-'));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../routing.mjs', import.meta.url)), '--verify', output],
        { timeout: 25000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.privateInputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      for (const record of report.records) {
        assert.equal(record.resource, null);
        assert.deepEqual(record.verification, {
          actualHttpsRequests: 19,
          deniedBeforeHandler: 7,
          handlerExecutions: 5,
          tenantImplementations: 2,
          foreignRowAbsent: true,
          emptyTenantHasNoFallback: true,
          capabilityLimit: 1,
          capabilityOverflowRejected: true,
          stableRevisionAndGeneration: true,
        });
        if (['STANDARD', 'DETAILED'].includes(record.mode)) {
          assert.equal(record.completion.technicalUsageEnabled, true);
          assert.equal(record.completion.routingChildren, 5);
          assert.equal(record.completion.tenantCount, 2);
          assert.equal(record.completion.duplicateChildByteCounters, 0);
          assert.ok(record.completion.httpParents >= 5);
        }
      }
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        { actualJwksRequests: 4, releaseGate: false },
      );
      assert.doesNotMatch(
        encoded,
        /owned-routing-(?:north|south)-row|unapproved-client-selection|Bearer |private-north-implementation|private-south-implementation/,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
