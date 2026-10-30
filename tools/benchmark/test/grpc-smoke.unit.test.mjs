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
  grpcUnaryReceipt,
  grpcReceiptDigest,
  grpcCorpusPayload,
  requireGrpcProcessTreeResource,
} from '../grpc-workload.mjs';

test('gRPC entry rejects unsupported campaigns and unmarked smoke before private PKI or evidence creation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_GRPC_BENCHMARK_DISPOSABLE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../grpc.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full gRPC campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('gRPC unary receipt validation preserves exact int64 strings and binary values without accepting extra authority', () => {
  const fixture = { marker: 'unit-private' },
    nonce = randomUUID(),
    input = {
      value: fixture.marker + '-unary-' + nonce,
      sequence: '9223372036854775807',
      payload: grpcCorpusPayload(),
    },
    receipt = grpcUnaryReceipt(fixture, input, { ...input });
  assert.deepEqual(receipt, { receipt: nonce, sequence: input.sequence, payloadHex: '00ff8007' });
  for (const changed of [
    { ...input, sequence: Number(input.sequence) },
    { ...input, payload: Buffer.from([0, 255, 128]) },
    { ...input, value: 'foreign-value' },
    { ...input, tenant: { tenantId: 'untrusted' } },
  ])
    assert.throws(() => grpcUnaryReceipt(fixture, input, changed));
  assert.throws(() =>
    grpcUnaryReceipt(
      fixture,
      { ...input, value: fixture.marker + '-unary-verification' },
      { ...input, value: fixture.marker + '-unary-verification' },
    ),
  );
});

test('gRPC aggregate integrity binds ordered private fixture receipts and the exact echoed protobuf corpus', () => {
  const rows = ['verification', randomUUID()].map((receipt) => ({
      receipt,
      sequence: '9223372036854775807',
      payloadHex: '00ff8007',
    })),
    digest = grpcReceiptDigest(rows);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.notEqual(grpcReceiptDigest([...rows].reverse()), digest);
  assert.equal(digest.includes(rows[1].receipt), false);
  assert.throws(() => grpcReceiptDigest([{ ...rows[1], sequence: '9223372036854775806' }]));
  assert.throws(() => grpcReceiptDigest([{ ...rows[1], payloadHex: '00ff8008' }]));
  assert.throws(() => grpcReceiptDigest(Array(513).fill(rows[0])));
});

test('gRPC sampling refuses missing or incomplete client descriptor resource observations', () => {
  // Policy validation input only; these are not measured resource observations.
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
  requireGrpcProcessTreeResource(resource);
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
    assert.throws(() => requireGrpcProcessTreeResource(changed));
});
