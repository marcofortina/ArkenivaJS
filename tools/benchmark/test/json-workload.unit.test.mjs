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
import { dataJsonPlugin, JSON_CAPABILITY } from '@arkenivajs/data-json';
import { nativeJson, verifyJson, jsonSettings } from '../json-workload.mjs';

test(
  'Native and public JSON workflows preserve explicit projection semantics and reject unknown catalogs',
  { timeout: 15000 },
  async () => {
    const app = await createApplication({
      service: { name: 'json-comparison-test', version: '1.0.0', environment: 'test' },
      plugins: [dataJsonPlugin(jsonSettings())],
    });
    try {
      await app.start();
      const actual = app.resolve(JSON_CAPABILITY);
      for (const service of [nativeJson(), actual]) {
        assert.equal(verifyJson(service, { marker: 'owned-json-test' }).operationsVerified, 4);
        assert.throws(() => service.parse('{"broken":'));
        assert.throws(() => service.validate({}, 'unknown'));
        assert.throws(() => service.transform({}, 'unknown'));
        assert.throws(() => service.transform({}, 'comparison.projection.v1'));
      }
      assert.throws(() => actual.parse('{"__proto__":{"polluted":true}}'));
      assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
      const value = actual.parse('{"nested":{"values":["001"]}}');
      assert.equal(Object.getPrototypeOf(value), null);
      assert.equal(Object.isFrozen(value.nested.values), true);
    } finally {
      await app.stop();
    }
  },
);

test(
  'Four JSON profiles verify actual native schema and declarative workflows without incomplete worker sampling',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-json-harness-'));
    const script = fileURLToPath(new URL('../json.mjs', import.meta.url));
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
      assert.doesNotMatch(encoded, /owned-json-private-value/);
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          operationsVerified: 4,
          schemaRejectionPathVerified: true,
          arrayOrderAndEmptyPreserved: true,
          missingOmittedAndNullPreserved: true,
          explicitScalarConversionVerified: true,
          inputUnchanged: true,
          deterministicSerializationVerified: true,
        });
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      const unsupported = join(directory, 'unsupported');
      await assert.rejects(
        promisify(execFile)(process.execPath, [script, '--smoke', unsupported], { timeout: 5000 }),
      );
      await assert.rejects(access(unsupported));
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
