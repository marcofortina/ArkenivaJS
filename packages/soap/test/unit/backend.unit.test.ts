// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, WSDL } from 'soap';
import { KitError } from '@arkenivajs/core';
import { inspectXml, inspectWsdl } from '../../dist/xml.js';
import { nativeWsdl, nativeClient } from '../../dist/backend.js';
import { contract, response } from '../fixture.js';

const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
test('The real native WSDL compiler describes actual document/literal operations without remote I/O', async () => {
  const wsdl = await nativeWsdl(contract);
  assert.ok(wsdl instanceof WSDL);
  const description = wsdl.describeServices() as {
    InventoryService: { InventoryPort: { ReadStock: unknown } };
  };
  assert.ok(description.InventoryService.InventoryPort.ReadStock);
  const client = await nativeClient(contract, 'https://inventory.fixture.invalid/soap');
  assert.ok(client instanceof Client);
  assert.deepEqual(client.describe(), description);
  await assert.rejects(client.ReadStockAsync({ sku: '001' }), code('EK_SOAP_WSDL'));
});
test('Actual node-soap XML decoding preserves the declared typed response and the real SOAP fault boundary', async () => {
  const wsdl = await nativeWsdl(contract);
  inspectXml(response);
  const result = wsdl.xmlToObject(response) as {
    Body: { ReadStockResponse: { quantity: number } };
  };
  assert.equal(result.Body.ReadStockResponse.quantity, 12);
  const fault =
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Server</faultcode><faultstring>private-fault</faultstring></s:Fault></s:Body></s:Envelope>';
  assert.throws(() => wsdl.xmlToObject(fault));
});
test('Native SAX guards reject DTD, entity expansion, undefined entities and malformed namespaces before SOAP parsing', () => {
  for (const value of [
    '<!DOCTYPE r [<!ENTITY secret SYSTEM "file:///private/document">]><r>&secret;</r>',
    '<!DOCTYPE r [<!ENTITY x "xxxxxxxx">]><r>&x;&x;</r>',
    '<r>&unknown;</r>',
    '<p:r/>',
    '<r xmlns:p="urn:x"><p:r></r>',
  ])
    assert.throws(() => inspectXml(value), code('EK_SOAP_WSDL'));
  assert.ok(inspectXml('<r><!-- <!DOCTYPE harmless> --><![CDATA[<!ENTITY text>]]></r>'));
});
test('WSDL imports are inventoried but never resolved implicitly by the native contract compiler', async () => {
  for (const location of [
    'https://remote.fixture.invalid/contract.wsdl',
    'file:///private/contract.wsdl',
    'relative.xsd',
  ]) {
    const value = contract.replace(
      '<types>',
      '<import namespace="urn:other" location="' + location + '"/><types>',
    );
    assert.deepEqual(inspectWsdl(value).imports, [location]);
    await assert.rejects(nativeWsdl(value), code('EK_UNSUPPORTED_CAPABILITY'));
  }
  const alias = contract.replace(
    '<xs:element name="ReadStock">',
    '<xs:import namespace="urn:other" location="file:///private/contract.xsd"/><xs:element name="ReadStock">',
  );
  assert.deepEqual(inspectWsdl(alias).imports, ['file:///private/contract.xsd']);
  await assert.rejects(nativeWsdl(alias), code('EK_UNSUPPORTED_CAPABILITY'));
  const foreign = contract.replace(
    '<types>',
    '<q:import xmlns:q="urn:foreign" location="file:///private/contract.wsdl"/><types>',
  );
  await assert.rejects(nativeWsdl(foreign), code('EK_SOAP_WSDL'));
});
test('Dangerous schema names, native method collisions and promise assimilation names fail before client construction', () => {
  for (const name of [
    '__proto__',
    'constructor',
    'prototype',
    'then',
    'describe',
    'setEndpoint',
    'wsdl',
    'emit',
    'on',
    '_events',
  ])
    assert.throws(() => inspectWsdl(contract.replaceAll('ReadStock', name)), code('EK_SOAP_WSDL'));
  for (const value of [
    contract.replace(
      'targetNamespace="urn:arkenivajs:stock"',
      'xmlns:q="__proto__" targetNamespace="urn:arkenivajs:stock"',
    ),
    contract.replace('type="xs:string"', 'type="xs:__proto__"'),
    contract.replace('<types>', '<types xml:base="file:///private/">'),
  ])
    assert.throws(() => inspectWsdl(value), code('EK_SOAP_WSDL'));
});

test('The actual native compiler preserves RPC/literal structure and document namespace serialization', async () => {
  const rpc = contract
    .replace('style="document"', 'style="rpc"')
    .replace(
      '<part name="parameters" element="tns:ReadStock"/>',
      '<part name="sku" type="xs:string"/>',
    )
    .replace(
      '<part name="parameters" element="tns:ReadStockResponse"/>',
      '<part name="quantity" type="xs:int"/>',
    );
  const native = await nativeWsdl(rpc),
    description = native.describeServices() as {
      InventoryService: { InventoryPort: { ReadStock: { input: unknown; output: unknown } } };
    };
  assert.ok(description.InventoryService.InventoryPort.ReadStock.input);
  assert.ok(description.InventoryService.InventoryPort.ReadStock.output);
  const document = await nativeWsdl(contract),
    xml = document.objectToDocumentXML(
      'ReadStock',
      { sku: '001 & <data>' },
      'tns',
      'urn:arkenivajs:stock',
    );
  assert.ok(xml.includes('001 &amp; &lt;data&gt;'));
  assert.ok(inspectXml(xml));
});
test('XML admission measures exact UTF-8 bytes, native depth and total attribute and element ceilings', () => {
  assert.ok(inspectXml('<r>é</r>', 9));
  assert.throws(() => inspectXml('<r>é</r>', 8), code('EK_SOAP_WSDL'));
  for (const value of [
    '<r>'.repeat(65) + '</r>'.repeat(65),
    '<r>' + '<x/>'.repeat(20000) + '</r>',
    '<r ' + Array.from({ length: 4097 }, (_, i) => 'a' + i + '="1"').join(' ') + '/>',
  ])
    assert.throws(() => inspectXml(value), code('EK_SOAP_WSDL'));
  assert.throws(() => inspectXml('"\ud800"'), code('EK_SOAP_WSDL'));
  assert.throws(() => inspectXml('<?xml version="1.1"?><r/>'), code('EK_UNSUPPORTED_CAPABILITY'));
  assert.throws(
    () => inspectXml('<?xml version="1.0" encoding="ISO-8859-1"?><r/>'),
    code('EK_UNSUPPORTED_CAPABILITY'),
  );
  assert.throws(() => inspectXml('<r><?work data?></r>'), code('EK_UNSUPPORTED_CAPABILITY'));
  assert.throws(() => inspectWsdl('<definitions xmlns="urn:wrong"/>'), code('EK_SOAP_WSDL'));
});
