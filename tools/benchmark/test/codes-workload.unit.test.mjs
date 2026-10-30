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
import { dataCodesPlugin, CODES_CAPABILITY } from '@arkenivajs/data-barcodes';
import {
  nativeCodes,
  codesFixture,
  codesSettings,
  verifyCodes,
  codesWorkload,
  codesOperations,
} from '../codes-workload.mjs';
import { codesPngFixture, codesPngDescriptor } from '../codes-fixture.mjs';

test(
  'Native and public barcode SDKs roundtrip all three symbologies and decode each other images',
  { timeout: 30000 },
  async () => {
    const app = await createApplication({
      service: { name: 'codes-comparison-unit', version: '1.0.0', environment: 'test' },
      plugins: [dataCodesPlugin(codesSettings)],
    });
    try {
      await app.start();
      const framework = app.resolve(CODES_CAPABILITY),
        native = nativeCodes();
      for (const service of [native, framework])
        assert.equal((await verifyCodes(service)).checkedPngRoundtrips, 3);
      for (const [symbology, text] of [
        ['QR', codesFixture.qr],
        ['CODE128', codesFixture.code128],
        ['EAN13', codesFixture.ean13],
      ]) {
        for (const [encoder, decoder] of [
          [native, framework],
          [framework, native],
        ]) {
          const image =
              symbology === 'QR'
                ? await encoder.generateQr(text)
                : await encoder.generateBarcode(text, symbology),
            before = Buffer.from(image);
          assert.deepEqual(await decoder.decode(image), [{ text, symbology }]);
          assert.deepEqual(Buffer.from(image), before);
        }
      }
    } finally {
      await app.stop();
    }
  },
);

test(
  'Barcode verification preserves actual codec evidence and refuses unapproved measurement modes before output',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-codes-harness-')),
      script = fileURLToPath(new URL('../codes.mjs', import.meta.url));
    try {
      const output = join(directory, 'verify');
      await promisify(execFile)(process.execPath, [script, '--verify', output], {
        timeout: 25000,
        maxBuffer: 1048576,
      });
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, false);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      for (const value of Object.values(codesFixture)) assert.equal(encoded.includes(value), false);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.collector.inputOccurrences, 0);
      for (const row of report.records) {
        assert.equal(row.resource, null);
        assert.equal(row.records.length, 0);
        assert.equal(row.verification.checkedPngRoundtrips, 3);
        assert.equal(row.verification.checkedSvgOutputs, 1);
        assert.equal(row.verification.actualNativeDecoding, true);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
      }
      for (const mode of ['--smoke', '--full']) {
        const rejected = join(directory, mode.slice(2));
        await assert.rejects(
          promisify(execFile)(process.execPath, [script, mode, rejected], {
            timeout: 5000,
            maxBuffer: 1048576,
            env: {
              ...process.env,
              ARKENIVA_CODES_BENCHMARK_DISPOSABLE: mode === '--smoke' ? '0' : '1',
            },
          }),
        );
        await assert.rejects(access(rejected), { code: 'ENOENT' });
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'The identical fixed decode PNG and one real operation per scenario have independently verified dimensions and contents',
  { timeout: 30000 },
  async () => {
    const app = await createApplication({
      service: { name: 'codes-single-operation', version: '1.0.0', environment: 'test' },
      plugins: [dataCodesPlugin(codesSettings)],
    });
    try {
      await app.start();
      const native = nativeCodes(),
        results = [];
      assert.deepEqual(await native.decode(codesPngFixture()), [
        { text: codesFixture.qr, symbology: 'QR' },
      ]);
      for (const service of [native, app.resolve(CODES_CAPABILITY)]) {
        const state = codesWorkload(service);
        for (const work of Object.values(state.workload)) await work();
        const completion = await state.complete(
          codesOperations.map((operation) => ({ operation, sampleCount: 1, warmupIterations: 0 })),
        );
        assert.equal(completion.independentlyVerified, true);
        assert.equal(completion.retainedOutputsAfterCompletion, 0);
        assert.equal(completion.fixedDecodeInputUnchanged, true);
        assert.ok(completion.retainedOutputBytes > 0 && completion.retainedOutputBytes <= 8388608);
        assert.equal(completion.summaries[3].inputSha256, codesPngDescriptor.sha256);
        assert.equal(completion.summaries[3].inputBytes, codesPngDescriptor.bytes);
        results.push(completion.summaries);
      }
      for (let index = 0; index < 3; index++) {
        assert.equal(results[0][index].width, results[1][index].width);
        assert.equal(results[0][index].height, results[1][index].height);
        assert.equal(results[0][index].pixels, results[1][index].pixels);
      }
    } finally {
      await app.stop();
    }
  },
);

test('Independent completion rejects a real decodable image carrying the wrong contents and clears retained outputs', async () => {
  const native = nativeCodes(),
    other = await native.generateQr('different-synthetic-code-payload', { widthPixels: 256 }),
    state = codesWorkload({ ...native, generateQr: async () => other });
  for (const work of Object.values(state.workload)) await work();
  const records = codesOperations.map((operation) => ({
    operation,
    sampleCount: 1,
    warmupIterations: 0,
  }));
  await assert.rejects(state.complete(records));
  await assert.rejects(state.workload['qr-png-encode']());
});
