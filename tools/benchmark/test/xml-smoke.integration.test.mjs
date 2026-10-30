// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { xmlFixture, xmlInvoice } from '../xml-workload.mjs';
import { assertXmlNamespace, xmlSchemaArtifacts, xmlNativeVersion } from '../xml-xsd.mjs';
import { assertRawLatencySamples } from './raw-latency.mjs';

test(
  'An owned isolated XML smoke retains real XSD decisions with independent fixed-document and validation-report checks',
  {
    timeout: 135000,
    skip: process.env.ARKENIVA_XML_DISPOSABLE !== '1' || process.env.ARKENIVA_XML_NS_ACTIVE !== '1',
  },
  async () => {
    await assertXmlNamespace();
    const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-xml-xsd-smoke-'));
    try {
      const output = join(directory, 'smoke');
      await promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../xml.mjs', import.meta.url)), '--smoke', output],
        { timeout: 130000, maxBuffer: 1048576, env: { ...process.env, TMPDIR: directory } },
      );
      assert.deepEqual(
        await readdir(directory),
        ['smoke'],
        'Owned XML schema and IPC snapshots must be physically removed',
      );
      const encoded = await readFile(join(output, 'report.json'), 'utf8'),
        report = JSON.parse(encoded);
      assert.equal(report.measured, true);
      assert.equal(report.releaseGate, false);
      assert.equal(report.records.length, 4);
      assert.equal(report.collector.inputOccurrences, 0);
      assert.ok(report.collector.receivedBodies >= 2);
      assert.equal(report.inputs.nativeXsdVersion, xmlNativeVersion);
      assert.deepEqual(report.inputs.xsdSchemaArtifacts, xmlSchemaArtifacts);
      for (const value of Object.values(xmlFixture)) assert.equal(encoded.includes(value), false);
      let samples = 0,
        validations = 0;
      for (const row of report.records) {
        assert.equal(row.verification.documentsVerified, 3);
        assert.equal(row.verification.realXsdVerified, true);
        assert.equal(row.verification.invoiceParserWriterVerified, true);
        assert.equal(row.verification.validXsdDocuments, 1);
        assert.equal(row.verification.invalidXsdDocuments, 1);
        assert.equal(row.verification.unknownSchemaRejected, true);
        assert.equal(row.records.length, 1);
        const record = row.records[0],
          completion = row.completion;
        assert.equal(record.operation, 'validate-xsd-invoice');
        assert.equal(record.sampleCount, 100);
        assert.equal(record.warmupIterations, 20);
        assertRawLatencySamples(record);
        assert.equal(completion.actualCallbacks, record.sampleCount + record.warmupIterations);
        assert.equal(completion.actualXsdValidations, completion.actualCallbacks);
        assert.equal(completion.checkedValidationReports, completion.actualCallbacks);
        assert.equal(completion.independentParseChecks, 1);
        assert.equal(completion.independentNativeXsdChecks, 1);
        assert.equal(completion.inputUnchanged, true);
        assert.equal(completion.retainedReportsAfterCompletion, 0);
        assert.equal(completion.inputBytes, xmlInvoice(xmlFixture).source.length);
        assert.equal(
          completion.consumedInputBytes,
          completion.inputBytes * completion.actualCallbacks,
        );
        assert.ok(
          completion.validationReportBytes > 0 && completion.validationReportBytes <= 65536,
        );
        assert.match(completion.inputSha256, /^[a-f0-9]{64}$/);
        assert.match(completion.validationReportSha256, /^[a-f0-9]{64}$/);
        const tree = row.processTreeResource;
        assert.equal(tree.scope, 'whole-supervised-lifecycle');
        assert.equal(tree.allChildrenWaited, true);
        assert.equal(tree.remainingOwnedProcesses, 0);
        assert.equal(tree.rssReadQuality.allObservedReadsAccessible, true);
        assert.equal(tree.rssReadQuality.inaccessibleReads, 0);
        assert.equal(tree.descendantDiscoveryQuality.inaccessibleReads, 0);
        assert.equal(tree.descendantDiscoveryQuality.traversalLimitExceeded, false);
        assert.ok(tree.observedProcessCount >= 3);
        assert.ok(tree.userCpuSeconds + tree.systemCpuSeconds > 0);
        assert.ok(tree.sampledSummedRssPeakBytes > 0);
        assert.equal(tree.pythonObserverIncluded, false);
        assert.equal(tree.externalServerResourcesIncluded, false);
        for (const pid of tree.observedPids) await assert.rejects(access('/proc/' + pid));
        assert.equal(row.quality !== null, ['STANDARD', 'DETAILED'].includes(row.mode));
        samples += record.sampleCount;
        validations += completion.actualCallbacks;
      }
      assert.equal(samples, 400);
      assert.equal(validations, 480);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
