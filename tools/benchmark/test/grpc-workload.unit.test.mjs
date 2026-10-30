// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm, access } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { grpcPlugin, GRPC_CAPABILITY } from '@arkenivajs/grpc';
import { mtlsPlugin } from '@arkenivajs/security-mtls';
import { startGrpcFixture } from '../grpc-fixture.mjs';
import {
  nativeGrpc,
  grpcConnection,
  grpcSettings,
  grpcMtlsSettings,
  verifyGrpc,
} from '../grpc-workload.mjs';

test('gRPC comparison rejects foreign endpoints and unowned trust bridge coordinates before I/O', () => {
  const fixture = {
    endpoint: 'localhost:1',
    descriptorFile: '/owned/echo.proto',
    bridgeUrl: 'http://127.0.0.1:1/verify',
    material: '{}',
  };
  for (const endpoint of [
    'foreign.invalid:443',
    'localhost:0',
    'localhost:65536',
    'http://localhost:1',
  ])
    assert.throws(() => grpcConnection({ ...fixture, endpoint }));
  for (const bridgeUrl of [
    'http://foreign.invalid:1/verify',
    'http://user:pass@127.0.0.1:1/verify',
    'http://127.0.0.1:1/verify?override=true',
  ])
    assert.throws(() => grpcConnection({ ...fixture, bridgeUrl }));
});

test(
  'Native and public gRPC preserve actual protobuf streams and fail closed on untrusted roots or unavailable revocation',
  { timeout: 30000 },
  async () => {
    const authority = await startGrpcFixture();
    const apps = [],
      baselines = [];
    const application = async (fixture) => {
      const app = await createApplication({
        service: { name: 'grpc-comparison-test', version: '1.0.0', environment: 'test' },
        plugins: [mtlsPlugin(grpcMtlsSettings(fixture)), grpcPlugin(grpcSettings(fixture))],
      });
      apps.push(app);
      await app.start();
      return app.resolve(GRPC_CAPABILITY);
    };
    try {
      const baseline = nativeGrpc(authority.fixture);
      baselines.push(baseline);
      const actual = await application(authority.fixture);
      for (const service of [baseline, actual])
        assert.equal((await verifyGrpc(service, authority.fixture)).actualOrderedStreamMessages, 3);
      const before = authority.verify(2).nativeChainAndCrlChecks;
      const denied = await globalThis.fetch(authority.fixture.bridgeUrl, {
        method: 'POST',
        headers: { authorization: 'Bearer invalid' },
        body: '{}',
      });
      assert.equal(denied.status, 400);
      await denied.arrayBuffer();
      assert.equal(authority.verify(2).nativeChainAndCrlChecks, before);
      const badFixture = {
        ...authority.fixture,
        material: JSON.stringify({
          ...JSON.parse(authority.fixture.material),
          ca: [authority.fixture.foreignCa],
        }),
      };
      const badNative = nativeGrpc(badFixture);
      baselines.push(badNative);
      await assert.rejects(
        badNative.client('Echo').unary('Bounce', { value: authority.fixture.marker + '-unary' }),
      );
      await assert.rejects(
        (async () => {
          const service = await application(badFixture);
          await service
            .client('Echo')
            .unary('Bounce', { value: authority.fixture.marker + '-unary' });
        })(),
      );
      authority.trustUnavailable(true);
      await assert.rejects(
        (async () => {
          const service = await application(authority.fixture);
          await service
            .client('Echo')
            .unary('Bounce', { value: authority.fixture.marker + '-unary' });
        })(),
      );
      assert.equal(authority.verify(2).actualUnaryCalls, 2);
    } finally {
      try {
        const closed = await Promise.allSettled([
          ...apps.map((app) => app.stop()),
          ...baselines.map((service) => service.close()),
        ]);
        assert.ok(closed.every((result) => result.status === 'fulfilled'));
      } finally {
        await authority.close();
      }
    }
  },
);

test(
  'Four gRPC profiles verify actual mutual-TLS unary/stream calls and independent server evidence',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-grpc-harness-'));
    const script = fileURLToPath(new URL('../grpc.mjs', import.meta.url));
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
      assert.doesNotMatch(
        encoded,
        /owned-grpc-private-value|arkenivajs-grpc-comparison-|127\.0\.0\.1|PRIVATE KEY/,
      );
      const protocol = JSON.parse(
        await readFile(join(output, 'protocol-observation.json'), 'utf8'),
      );
      assert.equal(protocol.actualUnaryCalls, 4);
      assert.equal(protocol.actualStreamCalls, 4);
      assert.equal(protocol.actualStreamedMessages, 12);
      assert.ok(protocol.nativeChainAndCrlChecks >= 3);
      assert.equal(protocol.releaseGate, false);
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          nativeClientIdentityVerified: true,
          actualUnaryVerified: true,
          exactInt64StringPreserved: true,
          binaryPayloadPreserved: true,
          actualOrderedStreamMessages: 3,
        });
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      const unsupported = join(directory, 'unsupported'),
        env = { ...process.env };
      delete env.ARKENIVA_GRPC_BENCHMARK_DISPOSABLE;
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', unsupported], {
          env,
          timeout: 5000,
        }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
