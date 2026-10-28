// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { nativeWsdl } from '../../dist/backend.js';
import { catalog } from '../../dist/catalog.js';
import { inspectEnvelope } from '../../dist/envelope.js';
import { capture, operation } from '../../dist/settings.js';
import type { SoapPluginSettings } from '../../dist/index.js';
import { contract, response } from '../fixture.js';

const settings: SoapPluginSettings = {
  services: [
    {
      id: 'stock.v1',
      wsdlFile: '/offline/stock.wsdl',
      endpoint: 'https://inventory.fixture.invalid/soap',
      allowedOperations: ['ReadStock'],
      protocol: '1.1',
      maxResponseBytes: 4096,
    },
  ],
  secretProvider: {
    async get() {
      throw new Error('No secret is configured');
    },
  },
  policy: { maxConcurrent: 1, timeoutMs: 10000 },
};
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
const assets = (source: string) => ({
  entry: '/offline/stock.wsdl',
  documents: [{ path: '/offline/stock.wsdl', source }],
});
test('Native catalog identifies exact qualified document operations and rejects unsupported protocol or allowlist entries', async () => {
  const native = await nativeWsdl(contract),
    entries = catalog(native, assets(contract), settings.services[0]!);
  assert.equal(entries.length, 1);
  assert.equal(entries[0]!.service, 'InventoryService');
  assert.equal(entries[0]!.port, 'InventoryPort');
  assert.equal(entries[0]!.action, 'urn:arkenivajs:ReadStock');
  assert.deepEqual(entries[0]!.input, { local: 'ReadStock', uri: 'urn:arkenivajs:stock' });
  assert.deepEqual(entries[0]!.output, { local: 'ReadStockResponse', uri: 'urn:arkenivajs:stock' });
  assert.ok(Object.isFrozen(entries) && Object.isFrozen(entries[0]));
  assert.throws(
    () => catalog(native, assets(contract), { ...settings.services[0]!, protocol: '1.2' }),
    code('EK_SOAP_WSDL'),
  );
  assert.throws(
    () =>
      catalog(native, assets(contract), {
        ...settings.services[0]!,
        allowedOperations: ['Unknown'],
      }),
    code('EK_SOAP_WSDL'),
  );
  const twelve = contract.replace(
    'http://schemas.xmlsoap.org/wsdl/soap/',
    'http://schemas.xmlsoap.org/wsdl/soap12/',
  );
  assert.equal(
    catalog(await nativeWsdl(twelve), assets(twelve), { ...settings.services[0]!, protocol: '1.2' })
      .length,
    1,
  );
});
test('Native RPC/literal output message names and native-compatible response aliases remain explicit', async () => {
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
  const entry = catalog(await nativeWsdl(rpc), assets(rpc), settings.services[0]!)[0]!;
  assert.equal(entry.input.local, 'ReadStock');
  assert.equal(entry.output.local, 'ReadStockOutput');
  assert.ok(entry.outputAliases?.includes('ReadStockResponse'));
});
test('Unknown QName prefixes, foreign WSDL declarations and duplicate native map keys fail before compilation', async () => {
  for (const source of [
    contract.replace('message="tns:ReadStockInput"', 'message="missing:ReadStockInput"'),
    contract
      .replace(
        '<message name="ReadStockInput">',
        '<q:message xmlns:q="urn:foreign" name="ReadStockInput">',
      )
      .replace('</message>', '</q:message>'),
    contract.replace('<types>', '<message name="ReadStockInput"/><types>'),
  ])
    await assert.rejects(nativeWsdl(source));
});
test('Envelope admission rejects wrong namespaces, duplicate bodies, payload ambiguity and wrapping', () => {
  const expected = [{ local: 'ReadStockResponse', uri: 'urn:arkenivajs:stock' }];
  assert.deepEqual(inspectEnvelope(response, '1.1', 4096, expected), expected[0]);
  for (const source of [
    response.replace('urn:arkenivajs:stock', 'urn:foreign'),
    response.replace('</s:Body>', '</s:Body><s:Body/>'),
    response.replace('</s:Body>', '<other xmlns="urn:arkenivajs:stock"/></s:Body>'),
    response.replace('<s:Body>', '<s:Body>private-text'),
    response.replace('</s:Body>', '</s:Body><s:Header/>'),
    response
      .replace('<s:Body>', '<q:Body xmlns:q="urn:foreign">')
      .replace('</s:Body>', '</q:Body>'),
    response.replace('ReadStockResponse', 'WrappedResponse'),
  ])
    assert.throws(() => inspectEnvelope(source, '1.1', 4096, expected), code('EK_SOAP_SCHEMA'));
});
test('Owned settings reject unknown fields, getters, proxies, duplicate profiles and invalid duration policies', () => {
  const captured = capture(settings);
  assert.equal(captured.services[0]!.id, 'stock.v1');
  assert.ok(Object.isFrozen(captured.services[0]!.allowedOperations));
  let getters = 0;
  const getter = Object.defineProperty({}, 'services', {
    get() {
      getters++;
      return settings.services;
    },
  });
  for (const input of [
    null,
    { ...settings, endpoint: 'https://other.invalid' },
    getter,
    new Proxy(settings, {}),
    { ...settings, services: [settings.services[0], settings.services[0]] },
    { ...settings, secretProvider: {} },
    {
      ...settings,
      services: [{ ...settings.services[0], endpoint: 'http://inventory.fixture.invalid' }],
    },
  ])
    assert.throws(() => capture(input as SoapPluginSettings), code('EK_CONFIG_INVALID'));
  assert.equal(getters, 0);
  for (const timeoutMs of [0, -1, 0.1, NaN, Infinity, 60001])
    assert.throws(
      () => capture({ ...settings, policy: { ...settings.policy, timeoutMs } }),
      code('EK_CONFIG_INVALID'),
    );
  assert.throws(() => operation({ timeoutMs: 0 }, 1000), code('EK_CONFIG_INVALID'));
  assert.throws(
    () => operation({ signal: Object.create(AbortSignal.prototype) }, 1000),
    code('EK_CONFIG_INVALID'),
  );
});
