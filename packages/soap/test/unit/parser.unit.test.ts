// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { NativeParser } from '../../dist/parser.js';
import { contract, response } from '../fixture.js';

const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;
const settings = {
  source: contract,
  protocol: '1.1' as const,
  timeoutMs: 10000,
  maxBytes: 1048576,
};
test('Owned native parser preserves typed responses and terminates its actual worker on idempotent close', async () => {
  const parser = await NativeParser.create(settings, new AbortController().signal);
  try {
    assert.ok(parser.worker.threadId > 0);
    const result = parser.parse(response) as { Body: { ReadStockResponse: { quantity: number } } };
    assert.equal(result.Body.ReadStockResponse.quantity, 12);
    for (let i = 0; i < 3; i++) assert.deepEqual(parser.parse(response), result);
  } finally {
    const closing = parser.close();
    assert.equal(parser.close(), closing);
    await closing;
  }
  assert.equal(parser.worker.threadId, -1);
  assert.throws(() => parser.parse(response), code('EK_RESOURCE_CLOSED'));
});
test('Malformed SOAP, JSON fallback, wrong envelopes and private faults return only sanitized public errors', async () => {
  const parser = await NativeParser.create(settings, new AbortController().signal);
  try {
    for (const source of [
      '{"private":"body"}',
      '<Envelope xmlns="urn:wrong"><Body/></Envelope>',
      '<!DOCTYPE s:Envelope [<!ENTITY x SYSTEM "file:///private/data">]>' + response,
      response.replace('quantity>12', 'quantity>&undefined;'),
      response.replaceAll(
        'http://schemas.xmlsoap.org/soap/envelope/',
        'http://www.w3.org/2003/05/soap-envelope',
      ),
    ])
      assert.throws(() => parser.parse(source), code('EK_SOAP_SCHEMA'));
    const fault =
      '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Server</faultcode><faultstring>private-fault-marker</faultstring></s:Fault></s:Body></s:Envelope>';
    assert.throws(
      () => parser.parse(fault),
      (error: unknown) => {
        assert.ok(error instanceof KitError);
        assert.equal(error.code, 'EK_SOAP_FAULT');
        assert.ok(!JSON.stringify(error).includes('private-fault-marker'));
        assert.ok(!error.message.includes('private-fault-marker'));
        return true;
      },
    );
    assert.ok(parser.parse(response));
  } finally {
    await parser.close();
  }
});
test('SOAP 1.2 parsing uses the same actual backend while enforcing its declared envelope version', async () => {
  const parser = await NativeParser.create(
    { ...settings, protocol: '1.2' },
    new AbortController().signal,
  );
  try {
    const result = parser.parse(
      response.replaceAll(
        'http://schemas.xmlsoap.org/soap/envelope/',
        'http://www.w3.org/2003/05/soap-envelope',
      ),
    ) as { Body: { ReadStockResponse: { quantity: number } } };
    assert.equal(result.Body.ReadStockResponse.quantity, 12);
    assert.throws(() => parser.parse(response), code('EK_SOAP_SCHEMA'));
  } finally {
    await parser.close();
  }
});
test('Worker startup is bounded and canceled startup does not leave a live parser', async () => {
  await assert.rejects(
    NativeParser.create({ ...settings, timeoutMs: 1 }, new AbortController().signal),
    code('EK_TIMEOUT'),
  );
  await assert.rejects(NativeParser.create(settings, AbortSignal.abort()), code('EK_ABORTED'));
  const controller = new AbortController();
  const pending = NativeParser.create(settings, controller.signal);
  controller.abort();
  await assert.rejects(pending, code('EK_ABORTED'));
  await assert.rejects(
    NativeParser.create({ ...settings, source: '<invalid/>' }, new AbortController().signal),
    code('EK_SOAP_WSDL'),
  );
});
test('Lifetime abort and unexpected native thread exit invalidate every subsequent call', async () => {
  const controller = new AbortController();
  const parser = await NativeParser.create(settings, controller.signal);
  controller.abort();
  assert.throws(() => parser.parse(response), code('EK_RESOURCE_CLOSED'));
  await parser.close();
  assert.equal(parser.worker.threadId, -1);
  const other = await NativeParser.create(settings, new AbortController().signal);
  await other.worker.terminate();
  await other.exited;
  assert.throws(() => other.parse(response), code('EK_RESOURCE_CLOSED'));
  await other.close();
});
test('An elapsed parsing deadline terminates native work and never silently restarts a retired worker', async () => {
  const parser = await NativeParser.create(settings, new AbortController().signal);
  const large = response.replace(
    '<quantity>12</quantity>',
    '<quantity>12</quantity>' + '<padding>bounded-native-parse-work</padding>'.repeat(15000),
  );
  try {
    assert.throws(() => parser.parse(large, 1), code('EK_TIMEOUT'));
    assert.throws(() => parser.parse(response), code('EK_RESOURCE_CLOSED'));
  } finally {
    await parser.close();
  }
  assert.equal(parser.worker.threadId, -1);
});
test('Invalid deadlines and byte ceilings fail before native execution without retiring a healthy worker', async () => {
  for (const value of [0, -1, 0.5, NaN, Infinity, 60001])
    await assert.rejects(
      NativeParser.create({ ...settings, timeoutMs: value }, new AbortController().signal),
      code('EK_CONFIG_INVALID'),
    );
  const parser = await NativeParser.create(
    { ...settings, maxBytes: Buffer.byteLength(response) },
    new AbortController().signal,
  );
  try {
    for (const value of [0, -1, 0.5, NaN, Infinity, 10001])
      assert.throws(() => parser.parse(response, value), code('EK_CONFIG_INVALID'));
    assert.throws(() => parser.parse(response + ' '), code('EK_SOAP_SCHEMA'));
    assert.ok(parser.parse(response));
  } finally {
    await parser.close();
  }
});
