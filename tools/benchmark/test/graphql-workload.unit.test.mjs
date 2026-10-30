// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { graphqlCoordinates } from '../graphql-workload.mjs';

test('GraphQL comparison rejects foreign issuers and ambiguous TLS fixture coordinates before I/O', () => {
  const valid = {
    issuer: 'http://127.0.0.1:1',
    privateKeyFile: '/owned/key',
    certificateFile: '/owned/cert',
    ca: 'owned-certificate',
  };
  graphqlCoordinates(valid);
  for (const issuer of [
    'http://foreign.invalid:1',
    'https://127.0.0.1:1',
    'http://u:p@127.0.0.1:1',
    'http://127.0.0.1:1/keys',
    'http://127.0.0.1:1?redirect=1',
  ])
    assert.throws(() => graphqlCoordinates({ ...valid, issuer }));
  for (const privateKeyFile of ['relative.key', '/owned/key\n', '/owned/key\0'])
    assert.throws(() => graphqlCoordinates({ ...valid, privateKeyFile }));
});

test(
  'Four actual HTTPS GraphQL profiles retain field and tenant denial, idempotency and real technical usage',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-graphql-harness-'));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../graphql.mjs', import.meta.url)), '--verify', output],
        { timeout: 25000, maxBuffer: 1048576 },
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      for (const record of report.records) {
        assert.equal(record.resource, null);
        assert.deepEqual(record.verification, {
          authenticatedRequests: 9,
          rejectedCredentials: 3,
          physicalMutations: 2,
          idempotencyReceipts: 2,
          deniedPrivateGetterReads: 0,
          isolatedTenants: 2,
        });
        if (['STANDARD', 'DETAILED'].includes(record.mode)) {
          assert.equal(record.completion.technicalUsageEnabled, true);
          assert.ok(record.completion.graphqlChildren >= 8);
          assert.equal(record.completion.tenantCount, 2);
          assert.equal(record.completion.duplicateGraphqlByteCounters, 0);
        }
      }
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        { actualJwksRequests: 4, releaseGate: false },
      );
      assert.doesNotMatch(
        encoded,
        /owned-customer|owned-private-note|same-owned-action|Bearer |synthetic-tenant|other-tenant/,
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
