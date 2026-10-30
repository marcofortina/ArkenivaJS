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
import { dataXmlPlugin, XML_CAPABILITY } from '@arkenivajs/data-xml';
import {
  nativeXml,
  verifyXml,
  xmlSettings,
  xmlFixture,
  xmlInvoice,
  xmlWorkload,
} from '../xml-workload.mjs';

test(
  'Native and public XML engines exchange ordered documents while rejecting malformed syntax and DTDs',
  { timeout: 15000 },
  async () => {
    const app = await createApplication({
      service: { name: 'xml-comparison-test', version: '1.0.0', environment: 'test' },
      plugins: [dataXmlPlugin(xmlSettings)],
    });
    try {
      await app.start();
      for (const service of [nativeXml(), app.resolve(XML_CAPABILITY)]) {
        const result = await verifyXml(service, {
          marker: 'owned-xml-test',
          namespace: 'urn:owned:xml:test',
        });
        assert.equal(result.documentsVerified, 3);
        await assert.rejects(service.parse('<r><c></r>'));
        await assert.rejects(
          service.parse('<!DOCTYPE r SYSTEM "https://foreign.invalid/entity"><r/>'),
        );
        await assert.rejects(service.parse(Uint8Array.of(0xff)));
      }
    } finally {
      await app.stop();
    }
  },
);

test(
  'Four XML verification profiles preserve parser/writer interoperability and refuse unapproved measurement modes',
  { timeout: 30000 },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-xml-harness-'));
    const script = fileURLToPath(new URL('../xml.mjs', import.meta.url));
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
      assert.doesNotMatch(encoded, /owned-xml-private|urn:owned:xml:private/);
      for (const row of report.records) {
        assert.deepEqual(row.verification, {
          documentsVerified: 3,
          mixedContentOrderVerified: true,
          leadingZeroAttributesPreserved: true,
          namespacePrefixesPreserved: true,
          entitiesAndUnicodeVerified: true,
          cdataAndCommentsPreserved: true,
          nativeWriterInteroperabilityVerified: true,
        });
        assert.deepEqual(row.records, []);
        assert.equal(row.resource, null);
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        if (row.quality) assert.ok(row.quality.metricSeries > 0);
      }
      for (const mode of ['--smoke', '--full']) {
        const unsupported = join(directory, mode.slice(2));
        await assert.rejects(
          promisify(execFile)(process.execPath, [script, mode, unsupported], {
            timeout: 5000,
            env: {
              ...process.env,
              ARKENIVA_XML_DISPOSABLE: mode === '--smoke' ? '0' : '1',
              ARKENIVA_XML_NS_ACTIVE: mode === '--smoke' ? '0' : '1',
            },
          }),
        );
        await assert.rejects(access(unsupported));
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);

test(
  'The fixed invoice has exact native/public ordered semantics and unavailable schema validation cannot produce completion evidence',
  { timeout: 15000 },
  async () => {
    const app = await createApplication({
      service: { name: 'xml-pipeline-bounded-control', version: '1.0.0', environment: 'test' },
      plugins: [dataXmlPlugin(xmlSettings)],
    });
    try {
      await app.start();
      const { source, expected } = xmlInvoice(xmlFixture),
        before = Buffer.from(source),
        native = nativeXml();
      for (const service of [native, app.resolve(XML_CAPABILITY)]) {
        const document = await service.parse(source);
        assert.deepEqual(JSON.parse(JSON.stringify(document)), expected);
        const encoded = await service.stringify(document);
        assert.deepEqual(JSON.parse(JSON.stringify(await native.parse(encoded))), expected);
        const state = xmlWorkload(service, xmlFixture);
        await assert.rejects(state.workload['validate-xsd-invoice']());
        await assert.rejects(
          state.complete([
            { operation: 'validate-xsd-invoice', sampleCount: 1, warmupIterations: 0 },
          ]),
        );
        assert.deepEqual(source, before);
      }
    } finally {
      await app.stop();
    }
  },
);
