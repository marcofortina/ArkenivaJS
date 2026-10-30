// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  soapReceiptDigest,
  verifySoapResult,
  requireSoapProcessTreeResource,
} from '../soap-workload.mjs';

test('SOAP entry rejects unsupported campaigns and unmarked smoke before certificate or evidence creation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_SOAP_BENCHMARK_DISPOSABLE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../soap.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full SOAP campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('SOAP result validation preserves decoded numeric scalars and distinguishes local correlation from server receipt', () => {
  const receipt = randomUUID(),
    valid = {
      status: 200,
      data: { quantity: 12 },
      correlationId: randomUUID(),
      headers: { 'x-owned-soap-receipt': receipt },
    };
  assert.equal(verifySoapResult(valid), receipt);
  for (const changed of [
    { ...valid, status: 500 },
    { ...valid, data: { quantity: '12' } },
    { ...valid, data: { quantity: 12, unexpected: true } },
    { ...valid, correlationId: '' },
    { ...valid, headers: {} },
    { ...valid, headers: { 'x-owned-soap-receipt': 'not-a-receipt' } },
  ])
    assert.throws(() => verifySoapResult(changed));
});

test('SOAP aggregate integrity binds exact private receipt order, input selection and numeric response', () => {
  const rows = [0, 1].map((index) => ({ receipt: randomUUID(), index, quantity: 12 })),
    digest = soapReceiptDigest(rows);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.notEqual(soapReceiptDigest([...rows].reverse()), digest);
  assert.notEqual(soapReceiptDigest([{ ...rows[0], index: 1 }, rows[1]]), digest);
  for (const row of rows) assert.equal(digest.includes(row.receipt), false);
  assert.throws(() => soapReceiptDigest([{ ...rows[0], quantity: '12' }]));
  assert.throws(() => soapReceiptDigest(Array(513).fill(rows[0])));
});

test('SOAP sampling refuses incomplete descendant and parser resource observations', () => {
  // Policy validation input only; these values are not measured resource evidence.
  const resource = {
    scope: 'whole-supervised-lifecycle',
    allChildrenWaited: true,
    remainingOwnedProcesses: 0,
    pythonObserverIncluded: false,
    externalServerResourcesIncluded: false,
    descendantDiscoveryQuality: { inaccessibleReads: 0, traversalLimitExceeded: false },
    rssReadQuality: { inaccessibleReads: 0, allObservedReadsAccessible: true },
    samplingRounds: 1,
    elapsedMs: 1,
    userCpuSeconds: 0,
    systemCpuSeconds: 0,
    maxSamplingGapMs: 1,
    largestSingleProcessRssBytes: 1,
    sampledSummedRssPeakBytes: 1,
    sampledLargestSingleRssBytes: 1,
  };
  requireSoapProcessTreeResource(resource);
  for (const changed of [
    undefined,
    { ...resource, remainingOwnedProcesses: 1 },
    { ...resource, allChildrenWaited: false },
    { ...resource, samplingRounds: 0 },
    { ...resource, rssReadQuality: { inaccessibleReads: 1, allObservedReadsAccessible: false } },
    {
      ...resource,
      descendantDiscoveryQuality: { inaccessibleReads: 0, traversalLimitExceeded: true },
    },
  ])
    assert.throws(() => requireSoapProcessTreeResource(changed));
});
