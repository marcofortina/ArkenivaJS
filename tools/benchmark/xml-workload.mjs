// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { TextDecoder } from 'node:util';
import { XMLParser, XMLBuilder } from 'fast-xml-parser';
import { SaxesParser } from 'saxes';

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
export function nativeXml() {
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
  return {
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
  return {
    documentsVerified: 3,
    mixedContentOrderVerified: true,
    leadingZeroAttributesPreserved: true,
    namespacePrefixesPreserved: true,
    entitiesAndUnicodeVerified: true,
    cdataAndCommentsPreserved: true,
    nativeWriterInteroperabilityVerified: true,
  };
}
