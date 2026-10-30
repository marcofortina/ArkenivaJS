// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { samlPlugin, SAML_CAPABILITY } from '@arkenivajs/security-saml';
import { runPureComparison } from '../pure-comparison.mjs';
import { startSamlFixture } from '../saml-fixture.mjs';
import {
  nativeSaml,
  samlSettings,
  prepareSamlRedirect,
  samlRedirectWorkload,
  verifySamlRedirect,
  samlPrivacyValues,
} from '../saml-workload.mjs';

test(
  'Native and public Redirect creation produces independently valid signed queries with fresh correlation',
  { timeout: 15000 },
  async () => {
    const authority = await startSamlFixture(),
      fixture = {
        ...authority.fixture,
        sampleReturnPath: '/owned-saml-correlation-' + randomBytes(16).toString('hex'),
      };
    let app;
    try {
      app = await createApplication({
        service: { name: 'saml-bounded-creation-test', version: '1.0.0', environment: 'test' },
        plugins: [samlPlugin(samlSettings(fixture))],
      });
      await app.start();
      for (const service of [nativeSaml(fixture), app.resolve(SAML_CAPABILITY)]) {
        prepareSamlRedirect(service, fixture);
        assert.equal(await samlRedirectWorkload(service).signedRedirectCreation(), true);
        const first = await service.beginLogin({ returnPath: fixture.sampleReturnPath }),
          second = await service.beginLogin({ returnPath: fixture.sampleReturnPath });
        assert.notEqual(first.requestId, second.requestId);
        for (const value of [first, second])
          assert.ok(verifySamlRedirect(value, fixture).signedQueryBytes > 0);
        const changed = new URL(first.redirectUrl);
        changed.searchParams.set('RelayState', second.requestId);
        assert.throws(() => verifySamlRedirect({ ...first, redirectUrl: changed.href }, fixture));
        assert.throws(() => verifySamlRedirect({ ...first, requestId: second.requestId }, fixture));
        const settings = JSON.parse(fixture.settings);
        assert.throws(() =>
          verifySamlRedirect(first, {
            ...fixture,
            settings: JSON.stringify({ ...settings, acsUrl: 'https://foreign.invalid/acs' }),
          }),
        );
        changed.searchParams.set('Signature', Buffer.alloc(256).toString('base64'));
        assert.throws(() => verifySamlRedirect({ ...first, redirectUrl: changed.href }, fixture));
      }
      assert.deepEqual(authority.observations(), { verifiedSignedRequests: 0, signedResponses: 0 });
    } finally {
      await app?.stop();
      await authority.close();
    }
  },
);

test(
  'The actual HTTP collector rejects SDK-created ID and protocol leakage from real SDK spans',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-privacy-')),
      marker = '/owned-saml-correlation-' + randomBytes(16).toString('hex');
    try {
      const worker = join(directory, 'sdk-control.mjs');
      await writeFile(
        worker,
        `
import { createTelemetry } from ${JSON.stringify(import.meta.resolve('@arkenivajs/telemetry'))};
process.once('message', async ({ mode, fixture, endpoint }) => {
  let telemetry;
  try {
    telemetry = createTelemetry({
      service: { name: 'saml-privacy-sdk-control', version: '1.0.0', environment: 'test' },
      mode: 'standard', samplingRatio: 1, endpoint, allowInsecureLoopback: true,
      exportTimeoutMs: 100, exportIntervalMs: 60000,
    });
    const span = telemetry.native().traces.getTracer('saml-privacy-control').startSpan('owned-control', {
      attributes: { 'owned.control': fixture.value },
    });
    span.end();
    await telemetry.flush();
    const quality = telemetry.stats();
    await telemetry.close();
    if (quality.exportFailures !== 0) throw new Error('The owned collector rejected this SDK export');
    process.send({ ok: true, result: { mode, verification: { actualSdkControl: true }, records: [], resource: null, quality } }, () => process.disconnect());
  } catch {
    await telemetry?.close();
    process.exitCode = 1;
    process.send({ ok: false }, () => process.disconnect());
  }
});
`,
        { mode: 0o600, flag: 'wx' },
      );
      const definition = (value) => ({
        scenarioId: 'saml-private-correlation-sdk-control',
        worker: pathToFileURL(worker),
        fixture: { value },
        privacyValues: samlPrivacyValues({ sampleReturnPath: marker }),
        privacyField: 'inputOccurrences',
        inputs: { syntheticControl: true },
        observationCoverage: 'Actual SDK HTTP export control only.',
        limitations: 'Functional privacy control; no workload measurement.',
      });
      const positive = await runPureComparison(definition('bounded-public-control'), [
        '--verify',
        join(directory, 'positive'),
      ]);
      assert.ok(positive.collector.receivedBodies >= 4);
      assert.equal(positive.collector.inputOccurrences, 0);
      assert.ok(positive.records.every((row) => row.verification.actualSdkControl));
      const negatives = [
        marker,
        '_' + randomBytes(20).toString('hex'),
        'SAMLRequest=synthetic-compressed-input',
        'RelayState=synthetic-correlation',
        '<samlp:AuthnRequest ID="synthetic"/>',
      ];
      for (const [index, value] of negatives.entries()) {
        const output = join(directory, 'negative-' + index);
        await assert.rejects(runPureComparison(definition(value), ['--verify', output]));
        await assert.rejects(access(join(output, 'report.json')), { code: 'ENOENT' });
      }
      const encoded = await readFile(join(directory, 'positive/report.json'), 'utf8');
      assert.equal(encoded.includes(marker), false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
