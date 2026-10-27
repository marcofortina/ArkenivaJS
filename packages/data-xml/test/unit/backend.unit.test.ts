// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import {
  parseNative,
  inputText,
  stringifyNative,
  documentSnapshot,
  preflight,
  schemaDependencies,
} from '../../dist/backend.js';
import { options, capture } from '../../dist/settings.js';

const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
test('Native XML preserves ordered mixed content, Unicode, leading zeros, comments and CDATA without coercion', () => {
  const document = parseNative(
    '<root id="001">a &amp; b<child>001</child>tail<![CDATA[<safe>]]><!--kept--></root>',
    options(undefined),
  );
  assert.equal(Object.getPrototypeOf(document.root), null);
  assert.ok(Object.isFrozen(document.root));
  assert.deepEqual(JSON.parse(JSON.stringify(document)), {
    root: {
      root: [
        { '#text': 'a & b' },
        { child: [{ '#text': '001' }] },
        { '#text': 'tail' },
        { '#cdata': [{ '#text': '<safe>' }] },
        { '#comment': [{ '#text': 'kept' }] },
      ],
      ':@': { '@_id': '001' },
    },
  });
  const unicode = parseNative(
    Buffer.from('\ufeff<?xml version="1.0" encoding="UTF-8"?><r>Ελληνικά שלום</r>'),
    options(undefined),
  );
  assert.deepEqual(JSON.parse(JSON.stringify(unicode.root)), { r: [{ '#text': 'Ελληνικά שלום' }] });
});
test('Expanded namespaces use native namespace resolution including rebinding and unqualified attributes', () => {
  const document = parseNative(
    '<p:r xmlns:p="urn:one" xmlns="urn:default" plain="x" p:id="v"><p:c xmlns:p="urn:two"/><c xml:lang="it"/></p:r>',
    options({ namespaceMode: 'expanded' }),
  );
  const value = JSON.parse(JSON.stringify(document.root));
  assert.ok(value['{urn:one}r']);
  assert.deepEqual(value[':@'], {
    '@_xmlns:p': 'urn:one',
    '@_xmlns': 'urn:default',
    '@_plain': 'x',
    '@_{urn:one}id': 'v',
  });
  assert.ok(value['{urn:one}r'][0]['{urn:two}c']);
  assert.ok(value['{urn:one}r'][1]['{urn:default}c']);
  assert.equal(value['{urn:one}r'][1][':@']['@_{http://www.w3.org/XML/1998/namespace}lang'], 'it');
});
test('Native SAX preflight rejects malformed XML, undefined entities and invalid namespace bindings', () => {
  for (const input of [
    '<r>&undefined;</r>',
    '<p:r/>',
    '<r a="1" a="2"/>',
    '<r><c></r>',
    '<r/><s/>',
    '<r>&#0;</r>',
    '<r>\0</r>',
    '<r xmlns:xml="urn:wrong"/>',
  ])
    assert.throws(() => parseNative(input, options(undefined)), code('EK_XML_PARSE'));
});
test('DTD, external entities and expansion bombs fail before the native tree parser', () => {
  for (const input of [
    '<!DOCTYPE r SYSTEM "http://127.0.0.1:1/never"><r/>',
    '<!DOCTYPE r [<!ENTITY local SYSTEM "file:///etc/passwd">]><r>&local;</r>',
    '<!DOCTYPE r [<!ENTITY a "payload"><!ENTITY b "&a;&a;">]><r>&b;</r>',
  ])
    assert.throws(() => parseNative(input, options(undefined)), code('EK_XML_SECURITY'));
  assert.doesNotThrow(() =>
    parseNative(
      '<r><!-- <!DOCTYPE literal> --><![CDATA[<!DOCTYPE literal>]]></r>',
      options(undefined),
    ),
  );
});
test('XML depth, total attribute count and exact UTF-8 input byte limits are enforced', () => {
  assert.doesNotThrow(() => parseNative('<r><c/></r>', options({ maxDepth: 2 })));
  assert.throws(
    () => parseNative('<r><c/></r>', options({ maxDepth: 1 })),
    code('EK_XML_SECURITY'),
  );
  assert.throws(
    () => parseNative('<r a="1"><c b="2"/></r>', options({ maxAttributes: 1 })),
    code('EK_XML_SECURITY'),
  );
  assert.doesNotThrow(() => parseNative('<r>é</r>', options({ maxBytes: 9 })));
  assert.throws(() => parseNative('<r>é</r>', options({ maxBytes: 8 })), code('EK_XML_SECURITY'));
});
test('Reserved JavaScript names cannot be renamed silently into alternate document properties', () => {
  for (const input of [
    '<__proto__/>',
    '<r constructor="x"/>',
    '<r><prototype/></r>',
    '<p:constructor xmlns:p="urn:test"/>',
  ])
    assert.throws(() => parseNative(input, options(undefined)), code('EK_XML_SECURITY'));
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
});
test('Input decoding rejects malformed UTF-8, unsupported XML versions and caller memory sharing', () => {
  assert.throws(
    () => parseNative(Uint8Array.of(0xc3, 0x28), options(undefined)),
    code('EK_XML_PARSE'),
  );
  assert.throws(
    () => parseNative('<?xml version="1.1"?><r/>', options(undefined)),
    code('EK_UNSUPPORTED_CAPABILITY'),
  );
  assert.throws(
    () => parseNative('<?xml version="1.0" encoding="UTF-16"?><r/>', options(undefined)),
    code('EK_UNSUPPORTED_CAPABILITY'),
  );
  assert.throws(
    () => inputText(new Uint8Array(new SharedArrayBuffer(4)), 4),
    code('EK_XML_SECURITY'),
  );
  assert.throws(() => inputText('\ud800', 8), code('EK_XML_SECURITY'));
  for (const bytes of [Uint8Array.of(0xff, 0xfe, 0x3c, 0), Uint8Array.of(0xfe, 0xff, 0, 0x3c)])
    assert.throws(() => inputText(bytes, 16), code('EK_UNSUPPORTED_CAPABILITY'));
});
test('Strict XML configuration is captured without filesystem access and forbids security relaxation', () => {
  const setting = {
    defaults: {},
    policy: { maxConcurrent: 2, timeoutMs: 1000 },
    xsdSchemaFiles: { invoice: '/offline/schemas/invoice.xsd' },
  };
  assert.equal(capture(setting).schemas.invoice, '/offline/schemas/invoice.xsd');
  for (const value of [
    null,
    { unknown: true },
    { forbidDtd: false },
    { externalEntities: true },
    { maxBytes: 0 },
    { maxDepth: 257 },
    { namespaceMode: 'remove' },
  ])
    assert.throws(() => options(value as never), code('EK_CONFIG_INVALID'));
  for (const value of [
    { ...setting, unknown: true },
    { ...setting, defaults: undefined },
    { ...setting, policy: { maxConcurrent: 9, timeoutMs: 1000 } },
    { ...setting, xsdSchemaFiles: { invoice: 'https://invalid.example/schema.xsd' } },
  ])
    assert.throws(() => capture(value as never), code('EK_CONFIG_INVALID'));
  let reads = 0;
  const dangerous = Object.defineProperty({}, 'maxBytes', {
    enumerable: true,
    get() {
      reads++;
      return 1;
    },
  });
  assert.throws(() => options(dangerous), code('EK_CONFIG_INVALID'));
  assert.equal(reads, 0);
});

test('The native builder roundtrips ordered content and expanded namespaces without namespace erasure', () => {
  for (const namespaceMode of ['preserve', 'expanded'] as const) {
    const policy = options({ namespaceMode });
    const document = parseNative(
      '<p:r xmlns:p="urn:one" xmlns="urn:default" plain="x" p:id="v">before<p:c xmlns:p="urn:two"/>after<![CDATA[<safe>]]><!--kept--></p:r>',
      policy,
    );
    const written = stringifyNative(document, policy);
    assert.deepEqual(parseNative(written, policy), document);
    assert.ok(written.includes('xmlns:p="urn:two"'));
    assert.ok(written.includes('<![CDATA[<safe>]]>'));
  }
});
test('Constructed document trees cannot inject elements through names, comments, CDATA or attributes', () => {
  const policy = options(undefined);
  for (const document of [
    { root: { r: [{ '#comment': [{ '#text': '--><injected/><!--' }] }] } },
    { root: { r: [{ '#cdata': [{ '#text': ']]><injected/><![CDATA[' }] }] } },
    { root: { 'r/><injected': [] } },
    { root: { r: [], ':@': { '@_a" injected="yes': 'x' } } },
    { root: { r: [{ '#text': 17 }] } },
    { root: { r: [{ '?unsafe': [] }] } },
  ])
    assert.throws(
      () => stringifyNative(document, policy),
      (error: unknown) => error instanceof KitError,
    );
  const written = stringifyNative(
    { root: { r: [{ '#text': '<safe>&"' }], ':@': { '@_a': '"><injected/>' } } },
    policy,
  );
  assert.equal(preflightForTest(written), 1);
});
function preflightForTest(xml: string) {
  const document = parseNative(xml, options(undefined));
  return Object.keys(document.root).filter((key) => key !== ':@').length;
}
test('Document snapshots reject accessors, cycles, sparse content, unsupported values and output expansion', () => {
  let reads = 0;
  const root = Object.defineProperty({}, 'r', {
    enumerable: true,
    get() {
      reads++;
      return [];
    },
  });
  assert.throws(() => documentSnapshot({ root }, options(undefined)), code('EK_XML_SECURITY'));
  assert.equal(reads, 0);
  const cyclic: Record<string, unknown> = {};
  cyclic.r = [cyclic];
  assert.throws(
    () => documentSnapshot({ root: cyclic }, options({ maxDepth: 4 })),
    code('EK_XML_SECURITY'),
  );
  assert.throws(
    () => documentSnapshot({ root: { r: new Array(1) } }, options(undefined)),
    code('EK_XML_SECURITY'),
  );
  assert.throws(
    () => stringifyNative({ root: { r: [{ '#text': '&&&&' }] } }, options({ maxBytes: 16 })),
    code('EK_XML_SECURITY'),
  );
  assert.throws(
    () =>
      stringifyNative({ root: { '{urn:missing}r': [] } }, options({ namespaceMode: 'expanded' })),
    code('EK_XML_SECURITY'),
  );
});

test('Native schema metadata cannot use XML base overrides and instance guards cannot select their own schemas', () => {
  const policy = options(undefined),
    namespace = 'http://www.w3.org/2001/XMLSchema';
  assert.deepEqual(
    schemaDependencies(
      '<x:schema xmlns:x="' + namespace + '"><x:include schemaLocation="types.xsd"/></x:schema>',
      policy,
    ),
    ['types.xsd'],
  );
  assert.throws(
    () =>
      schemaDependencies('<x:schema xmlns:x="' + namespace + '" xml:base="file:///etc/"/>', policy),
    code('EK_XML_SECURITY'),
  );
  assert.throws(
    () =>
      preflight(
        '<r xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:schemaLocation="http://127.0.0.1:1/schema.xsd"/>',
        policy,
        true,
      ),
    code('EK_XML_SECURITY'),
  );
});

test('XML tree node admission is enforced before allocation and malformed metadata nesting cannot overflow the main stack', () => {
  assert.throws(
    () => parseNative('<r>' + '<c/>'.repeat(100000) + '</r>', options(undefined)),
    code('EK_XML_SECURITY'),
  );
  let nested: Record<string, unknown> = { '#text': 'data' };
  for (let i = 0; i < 300; i++) nested = { '#cdata': [nested] };
  assert.throws(
    () => documentSnapshot({ root: { r: [nested] } }, options({ maxDepth: 32 })),
    code('EK_XML_SECURITY'),
  );
});
