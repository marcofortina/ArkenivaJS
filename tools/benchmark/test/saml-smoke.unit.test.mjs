// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { Server } from 'node:http';
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
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-saml-privacy-')),
      marker = '/owned-saml-correlation-' + randomBytes(16).toString('hex');
    const responses = [];
    let responseOverflow = false;
    const originalEmit = Server.prototype.emit;
    // Observe completed owned collector responses without touching their protocol or payload.
    t.mock.method(Server.prototype, 'emit', function (event, ...args) {
      if (
        event === 'request' &&
        this.address()?.address === '127.0.0.1' &&
        args[0]?.method === 'POST' &&
        ['/v1/metrics', '/v1/traces'].includes(args[0]?.url)
      )
        args[1].once('finish', () => {
          if (responses.length === 256) responseOverflow = true;
          else responses.push(args[1].statusCode);
        });
      return Reflect.apply(originalEmit, this, [event, ...args]);
    });
    const modes = ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'];
    const phases = ['setup', 'span', 'flush', 'stats', 'close', 'complete'];
    const errorNames = ['Error', 'KitError', 'TypeError', 'OTHER'];
    const errorCodes = ['EK_TIMEOUT', 'EK_BACKEND_UNAVAILABLE', 'NONE', 'OTHER'];
    const qualityFields = [
      'spansStarted',
      'spansEnded',
      'droppedSpans',
      'pendingSpans',
      'activeSpans',
      'exportFailures',
      'droppedMetrics',
      'instruments',
      'metricSeries',
    ];
    const diagnostics = async (output) => {
      const rows = [];
      for (const mode of modes) {
        let encoded;
        try {
          encoded = await readFile(join(output, mode + '.json'), 'utf8');
        } catch (error) {
          if (error.code === 'ENOENT') continue;
          assert.fail('The owned SDK diagnostic could not be read');
        }
        assert.ok(encoded.length <= 4096, 'The owned SDK diagnostic exceeded its bound');
        const row = JSON.parse(encoded);
        assert.deepEqual(Object.keys(row).sort(), ['code', 'name', 'outcome', 'phase', 'quality']);
        assert.ok(phases.includes(row.phase));
        assert.ok(['success', 'failure'].includes(row.outcome));
        assert.ok(errorNames.includes(row.name) && errorCodes.includes(row.code));
        assert.ok(Object.keys(row.quality).every((key) => qualityFields.includes(key)));
        assert.ok(
          Object.values(row.quality).every((value) => Number.isSafeInteger(value) && value >= 0),
        );
        rows.push({ mode, ...row });
      }
      return rows;
    };
    try {
      const worker = join(directory, 'sdk-control.mjs');
      await writeFile(
        worker,
        `
import { createTelemetry } from ${JSON.stringify(import.meta.resolve('@arkenivajs/telemetry'))};
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
process.once('message', async ({ mode, fixture, endpoint }) => {
  let telemetry, phase = 'setup';
  const safeQuality = () => {
    const result = {};
    for (const [key, value] of Object.entries(telemetry?.stats() ?? {}))
      if (${JSON.stringify(qualityFields)}.includes(key) && Number.isSafeInteger(value) && value >= 0)
        result[key] = value;
    return result;
  };
  const diagnostic = async (outcome, error) => {
    if (!${JSON.stringify(modes)}.includes(mode)) throw new Error('Invalid owned SDK mode');
    const name = error === undefined ? 'Error' : ${JSON.stringify(errorNames)}.includes(error?.name) ? error.name : 'OTHER';
    const code = error === undefined ? 'NONE' : ${JSON.stringify(errorCodes)}.includes(error?.code) ? error.code : 'OTHER';
    await writeFile(join(fixture.diagnostics, mode + '.json'), JSON.stringify({ phase, outcome, name, code, quality: safeQuality() }), { mode: 0o600, flag: 'wx' });
  };
  try {
    telemetry = createTelemetry({
      service: { name: 'saml-privacy-sdk-control', version: '1.0.0', environment: 'test' },
      mode: 'standard', samplingRatio: 1, endpoint, allowInsecureLoopback: true,
      exportTimeoutMs: 1000, exportIntervalMs: 60000,
    });
    phase = 'span';
    const span = telemetry.native().traces.getTracer('saml-privacy-control').startSpan('owned-control', {
      attributes: { 'owned.control': fixture.value },
    });
    span.end();
    phase = 'flush';
    await telemetry.flush();
    phase = 'stats';
    const quality = telemetry.stats();
    phase = 'close';
    await telemetry.close();
    if (quality.exportFailures !== 0) throw new Error('The owned collector rejected this SDK export');
    phase = 'complete';
    await diagnostic('success');
    process.send({ ok: true, result: { mode, verification: { actualSdkControl: true }, records: [], resource: null, quality } }, () => process.disconnect());
  } catch (error) {
    try { await diagnostic('failure', error); } finally {
      try { await telemetry?.close(); } catch {}
    }
    process.exitCode = 1;
    process.send({ ok: false }, () => process.disconnect());
  }
});
`,
        { mode: 0o600, flag: 'wx' },
      );
      const definition = (value, output) => ({
        scenarioId: 'saml-private-correlation-sdk-control',
        worker: pathToFileURL(worker),
        fixture: { value, diagnostics: output },
        privacyValues: samlPrivacyValues({ sampleReturnPath: marker }),
        privacyField: 'inputOccurrences',
        inputs: { syntheticControl: true },
        observationCoverage: 'Actual SDK HTTP export control only.',
        limitations: 'Functional privacy control; no workload measurement.',
      });
      const positiveOutput = join(directory, 'positive');
      let positive;
      try {
        positive = await runPureComparison(definition('bounded-public-control', positiveOutput), [
          '--verify',
          positiveOutput,
        ]);
      } catch {
        assert.fail(
          'The positive SDK control failed: ' + JSON.stringify(await diagnostics(positiveOutput)),
        );
      }
      assert.equal(responseOverflow, false);
      assert.ok(responses.length >= 4);
      assert.ok(responses.every((status) => status === 200));
      assert.ok(positive.collector.receivedBodies >= 4);
      assert.equal(positive.collector.inputOccurrences, 0);
      assert.ok(positive.records.every((row) => row.verification.actualSdkControl));
      const positiveDiagnostics = await diagnostics(positiveOutput);
      assert.equal(positiveDiagnostics.length, 4);
      assert.ok(positiveDiagnostics.every((row) => row.outcome === 'success'));
      t.diagnostic('Positive SDK control: ' + JSON.stringify(positiveDiagnostics));
      const negatives = [
        marker,
        '_' + randomBytes(20).toString('hex'),
        'SAMLRequest=synthetic-compressed-input',
        'RelayState=synthetic-correlation',
        '<samlp:AuthnRequest ID="synthetic"/>',
      ];
      for (const [index, value] of negatives.entries()) {
        const output = join(directory, 'negative-' + index);
        const before = responses.length;
        await assert.rejects(runPureComparison(definition(value, output), ['--verify', output]));
        const observed = responses.slice(before);
        const safeDiagnostics = await diagnostics(output);
        assert.equal(responseOverflow, false);
        assert.ok(
          observed.includes(500),
          'The negative SDK control did not observe a collector rejection: ' +
            JSON.stringify(safeDiagnostics),
        );
        t.diagnostic(
          'Negative SDK control ' +
            index +
            ': ' +
            JSON.stringify({ statuses: observed, diagnostics: safeDiagnostics }),
        );
        await assert.rejects(access(join(output, 'report.json')), { code: 'ENOENT' });
      }
      const encoded = await readFile(join(directory, 'positive/report.json'), 'utf8');
      assert.equal(encoded.includes(marker), false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
