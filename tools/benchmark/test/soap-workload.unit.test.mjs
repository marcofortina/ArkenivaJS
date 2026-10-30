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
import { soapPlugin, SOAP_CAPABILITY } from '@arkenivajs/soap';
import { startSoapFixture } from '../soap-fixture.mjs';
import { nativeSoap, soapSettings, soapConnection, verifySoap } from '../soap-workload.mjs';

test('SOAP comparison rejects foreign endpoints and transport ambiguity before I/O', () => {
  const fixture = {
    endpoint: 'https://127.0.0.1:1/soap',
    certificateFile: '/owned/ca',
    wsdlFile: '/owned/wsdl',
  };
  for (const endpoint of [
    'http://127.0.0.1:1/soap',
    'https://foreign.invalid:443/soap',
    'https://127.0.0.1:1/soap?override=true',
    'https://user:pass@127.0.0.1:1/soap',
  ])
    assert.throws(() => soapConnection({ ...fixture, endpoint }));
});

test(
  'Native and public SOAP make actual HTTPS calls and reject a wrong hostname or untrusted CA after healthy controls',
  { timeout: 30000 },
  async () => {
    const authority = await startSoapFixture();
    let app, untrusted, baseline, wrong, badApp;
    try {
      app = await createApplication({
        service: { name: 'soap-comparison-test', version: '1.0.0', environment: 'test' },
        plugins: [soapPlugin(soapSettings(authority.fixture))],
      });
      await app.start();
      baseline = await nativeSoap(authority.fixture);
      for (const service of [baseline, app.resolve(SOAP_CAPABILITY)])
        assert.equal((await verifySoap(service, authority.fixture)).actualHttpsCallsVerified, 2);
      wrong = await nativeSoap(authority.fixture, true);
      const badNativeClient = await wrong.createClient('comparison.v1');
      try {
        await assert.rejects(
          badNativeClient.call('ReadStock', { sku: authority.fixture.marker + '-0' }),
        );
      } finally {
        await badNativeClient.close();
      }
      untrusted = await startSoapFixture();
      badApp = await createApplication({
        service: { name: 'soap-untrusted-test', version: '1.0.0', environment: 'test' },
        plugins: [
          soapPlugin(
            soapSettings({
              ...authority.fixture,
              certificateFile: untrusted.fixture.certificateFile,
            }),
          ),
        ],
      });
      await badApp.start();
      const badPublicClient = await badApp.resolve(SOAP_CAPABILITY).createClient('comparison.v1');
      try {
        await assert.rejects(
          badPublicClient.call('ReadStock', { sku: authority.fixture.marker + '-0' }),
        );
      } finally {
        await badPublicClient.close();
      }
      assert.equal(authority.verify(4).actualNativeRequests, 4);
      assert.equal(untrusted.verify(0).actualNativeRequests, 0);
    } finally {
      try {
        const cleanup = await Promise.allSettled([
          badApp?.stop(),
          app?.stop(),
          wrong?.close(),
          baseline?.close(),
        ]);
        assert.ok(cleanup.every((result) => result.status === 'fulfilled'));
      } finally {
        try {
          await untrusted?.close();
        } finally {
          await authority.close();
        }
      }
    }
  },
);

test(
  'Four SOAP profiles verify actual HTTPS/native WSDL calls and independent server observations',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-soap-harness-'));
    const script = fileURLToPath(new URL('../soap.mjs', import.meta.url));
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
        /owned-soap-private-sku|arkenivajs-soap-comparison-|127\.0\.0\.1/,
      );
      assert.deepEqual(
        JSON.parse(await readFile(join(output, 'protocol-observation.json'), 'utf8')),
        { actualNativeRequests: 8, distinctInputsVerified: true, releaseGate: false },
      );
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          actualHttpsCallsVerified: 2,
          nativeClientIdentityVerified: true,
          approvedOperationVerified: true,
          actualHttpStatusVerified: true,
          distinctCorrelationIdsVerified: true,
        });
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      const unsupported = join(directory, 'unsupported'),
        env = { ...process.env };
      delete env.ARKENIVA_SOAP_BENCHMARK_DISPOSABLE;
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
