// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';
import { SaxesParser } from 'saxes';
import { nativeXsd } from './xml-xsd.mjs';

export const xmlFixture = Object.freeze({
  marker: 'owned-xml-private-value-π',
  namespace: 'urn:owned:xml:private',
});

export const xmlSettings = Object.freeze({
  defaults: {
    maxBytes: 4096,
    maxDepth: 16,
    maxAttributes: 32,
    namespaceMode: 'preserve',
    forbidDtd: true,
    externalEntities: false,
  },
  policy: { maxConcurrent: 2, timeoutMs: 2000, maxInputBytes: 4096, maxOutputBytes: 8192 },
});
const plain = (value) => JSON.parse(JSON.stringify(value));

/** Native libraries own syntax, namespace validation, ordered parsing and serialization. */
export function nativeXml(fixture) {
  const parser = new XMLParser({
    preserveOrder: true,
    ignoreAttributes: false,
    parseTagValue: false,
    parseAttributeValue: false,
    trimValues: false,
    ignoreDeclaration: true,
    cdataPropName: '#cdata',
    commentPropName: '#comment',
    maxNestedTags: 16,
    jPath: false,
    processEntities: {
      enabled: true,
      maxExpandedLength: 4096,
      maxTotalExpansions: 4096,
      maxEntityCount: 1,
    },
  });
  const builder = new XMLBuilder({
    preserveOrder: true,
    ignoreAttributes: false,
    cdataPropName: '#cdata',
    commentPropName: '#comment',
    processEntities: true,
    format: false,
  });
  let validator;
  const service = {
    async parse(input) {
      const source =
        typeof input === 'string' ? input : new TextDecoder('utf-8', { fatal: true }).decode(input);
      const sax = new SaxesParser({ xmlns: true });
      sax.on('doctype', () => {
        throw new Error('The native XML comparison does not accept DTDs');
      });
      sax.write(source).close();
      const roots = parser
        .parse(source)
        .filter((node) =>
          Object.keys(node).some(
            (key) => key !== ':@' && !key.startsWith('#') && !key.startsWith('?'),
          ),
        );
      assert.equal(roots.length, 1);
      return { root: roots[0] };
    },
    stringify: async (document) => builder.build([document.root]),
    async validateXsd(input, id) {
      assert.ok(fixture?.xsd, 'The native XSD comparison backend was not configured');
      await service.parse(input);
      validator ??= nativeXsd(fixture.xsd);
      return (await validator)(input, id);
    },
  };
  return service;
}

export function xmlInvoice(fixture, invalid = false) {
  const amount = invalid ? fixture.marker : '12.50';
  const source = Buffer.from(
    `<invoice xmlns="urn:arkenivajs:invoice"><id>${fixture.marker}</id><amount>${amount}</amount></invoice>`,
    'utf8',
  );
  return {
    source,
    expected: {
      root: {
        invoice: [{ id: [{ '#text': fixture.marker }] }, { amount: [{ '#text': amount }] }],
        ':@': { '@_xmlns': 'urn:arkenivajs:invoice' },
      },
    },
  };
}

/** Measure only real XSD decisions; verify the fixed document and all retained reports independently. */
export function xmlWorkload(service, fixture) {
  const { source, expected } = xmlInvoice(fixture),
    before = Buffer.from(source),
    reports = [],
    expectedReport = { valid: true, messages: [] };
  let validated = 0,
    retainedBytes = 0,
    completed = false;
  return {
    workload: {
      async 'validate-xsd-invoice'() {
        assert.equal(completed, false);
        assert.ok(reports.length < 120, 'The XML validation report capacity is exceeded');
        const result = await service.validateXsd(source, 'invoice');
        assert.deepEqual(result, expectedReport);
        assert.deepEqual(source, before);
        const encoded = JSON.stringify(result),
          bytes = Buffer.byteLength(encoded);
        assert.ok(bytes > 0 && bytes <= 512 && retainedBytes + bytes <= 65536);
        validated++;
        reports.push(encoded);
        retainedBytes += bytes;
        return result.valid;
      },
    },
    async complete(records) {
      assert.equal(completed, false);
      completed = true;
      try {
        assert.equal(records.length, 1);
        assert.equal(records[0].operation, 'validate-xsd-invoice');
        const count = records[0].sampleCount + records[0].warmupIterations;
        assert.ok(Number.isSafeInteger(count) && count > 0 && count <= 120);
        assert.equal(reports.length, count);
        assert.equal(validated, count);
        assert.deepEqual(source, before);
        const independent = nativeXml(fixture),
          digest = createHash('sha256');
        assert.deepEqual(plain(await independent.parse(source)), expected);
        assert.deepEqual(await independent.validateXsd(source, 'invoice'), expectedReport);
        for (const encoded of reports) {
          assert.deepEqual(JSON.parse(encoded), expectedReport);
          digest.update(encoded);
        }
        return {
          actualCallbacks: count,
          actualXsdValidations: validated,
          checkedValidationReports: reports.length,
          independentParseChecks: 1,
          independentNativeXsdChecks: 1,
          inputBytes: source.length,
          consumedInputBytes: source.length * count,
          inputSha256: createHash('sha256').update(source).digest('hex'),
          validationReportBytes: retainedBytes,
          validationReportSha256: digest.digest('hex'),
          inputUnchanged: true,
          retainedReportsAfterCompletion: 0,
        };
      } finally {
        reports.length = 0;
      }
    },
  };
}

export async function verifyXml(service, fixture) {
  const first = `<r id="001">before<c code="0007">${fixture.marker} &amp; €</c>after</r>`;
  const second = `<p:r xmlns:p="${fixture.namespace}" p:id="001"><p:c>${fixture.marker}</p:c></p:r>`;
  const expected = [
    {
      root: {
        r: [
          { '#text': 'before' },
          { c: [{ '#text': fixture.marker + ' & €' }], ':@': { '@_code': '0007' } },
          { '#text': 'after' },
        ],
        ':@': { '@_id': '001' },
      },
    },
    {
      root: {
        'p:r': [{ 'p:c': [{ '#text': fixture.marker }] }],
        ':@': { '@_xmlns:p': fixture.namespace, '@_p:id': '001' },
      },
    },
  ];
  const native = nativeXml();
  for (const [index, source] of [first, second].entries()) {
    const document = await service.parse(Buffer.from(source, 'utf8'));
    assert.deepEqual(plain(document), expected[index]);
    const encoded = await service.stringify(document);
    assert.equal(typeof encoded, 'string');
    assert.deepEqual(plain(await native.parse(encoded)), expected[index]);
    assert.deepEqual(plain(await service.parse(encoded)), expected[index]);
    const nativeEncoded = await native.stringify(expected[index]);
    assert.deepEqual(plain(await service.parse(nativeEncoded)), expected[index]);
  }
  const special = `<r><![CDATA[<raw>&${fixture.marker}]]><!--kept--></r>`;
  const specialDocument = await service.parse(special);
  assert.deepEqual(plain(specialDocument), plain(await native.parse(special)));
  const specialEncoded = await service.stringify(specialDocument);
  assert.ok(specialEncoded.includes('<![CDATA['));
  assert.ok(specialEncoded.includes('<!--kept-->'));
  assert.deepEqual(plain(await native.parse(specialEncoded)), plain(specialDocument));
  let xsd;
  if (fixture.xsd) {
    const { source: valid, expected: invoiceTree } = xmlInvoice(fixture),
      invalid = xmlInvoice(fixture, true).source;
    const invoiceDocument = await service.parse(valid);
    assert.deepEqual(plain(invoiceDocument), invoiceTree);
    const encodedInvoice = await service.stringify(invoiceDocument);
    assert.deepEqual(plain(await native.parse(encodedInvoice)), invoiceTree);
    assert.equal((await service.validateXsd(valid, 'invoice')).valid, true);
    const rejected = await service.validateXsd(invalid, 'invoice');
    assert.equal(rejected.valid, false);
    assert.equal(JSON.stringify(rejected).includes(fixture.marker), false);
    await assert.rejects(service.validateXsd(valid, 'unregistered-comparison-schema'));
    xsd = {
      realXsdVerified: true,
      invoiceParserWriterVerified: true,
      validXsdDocuments: 1,
      invalidXsdDocuments: 1,
      unknownSchemaRejected: true,
    };
  }
  return {
    documentsVerified: 3,
    mixedContentOrderVerified: true,
    leadingZeroAttributesPreserved: true,
    namespacePrefixesPreserved: true,
    entitiesAndUnicodeVerified: true,
    cdataAndCommentsPreserved: true,
    nativeWriterInteroperabilityVerified: true,
    ...xsd,
  };
}
