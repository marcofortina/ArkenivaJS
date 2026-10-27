// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { createApplication, KitError } from '@arkenivajs/core';
import { dataJsonPlugin, JSON_CAPABILITY } from '../../dist/index.js';
import type { JsonService, DataJsonPluginSettings, JsonMappingV1 } from '../../dist/index.js';
import { Runtime } from '../../dist/runtime.js';
import { capture } from '../../dist/settings.js';

const mapping: JsonMappingV1 = {
  schemaVersion: '1.0.0',
  id: 'summary.v1',
  inputSchemaId: 'input',
  outputSchemaId: 'output',
  fields: {
    id: { op: 'copy', path: '/id', required: true },
    active: { op: 'to-boolean', value: { op: 'copy', path: '/active', required: true } },
  },
  limits: { maxDepth: 8, maxNodes: 32, maxArrayItems: 16, maxOutputBytes: 4096 },
};
const settings: DataJsonPluginSettings = {
  defaults: { maxBytes: 4096, maxDepth: 16 },
  schemas: {
    input: {
      type: 'object',
      properties: { id: { type: 'string' }, active: { type: 'string' } },
      required: ['id', 'active'],
    },
    output: {
      type: 'object',
      properties: { id: { type: 'string' }, active: { type: 'boolean' } },
      required: ['id', 'active'],
      additionalProperties: false,
    },
  },
  mappings: { ids: [mapping.id], get: () => mapping },
  policy: { maxConcurrent: 1, timeoutMs: 3000, maxInputBytes: 4096, maxOutputBytes: 8192 },
};
const code = (name: string) => (error: unknown) => error instanceof KitError && error.code === name;

test('The explicit public JSON capability executes actual native workers synchronously and closes with its application', async () => {
  const app = await createApplication({
    service: { name: 'json-runtime', version: '1.0.0', environment: 'test' },
    plugins: [dataJsonPlugin(settings)],
  });
  await app.start();
  const json = app.resolve<JsonService>(JSON_CAPABILITY);
  try {
    const value = json.parse('{"id":"001","active":"true"}');
    assert.equal(typeof json.stringify(value), 'string');
    assert.ok(!(value instanceof Promise));
    assert.equal(json.validate(value, 'input').valid, true);
    const transformed = json.transform(value, mapping.id) as Record<string, unknown>;
    assert.equal(transformed.id, '001');
    assert.equal(transformed.active, true);
    assert.ok(Object.isFrozen(transformed));
    assert.equal(Object.getPrototypeOf(transformed), null);
    assert.equal(json.stringify(transformed), ' {"id":"001","active":true}'.trim());
    assert.equal(json.validate({ id: 1, active: 'true' }, 'input').valid, false);
    assert.throws(
      () => json.transform({ id: '001', active: 'TRUE' }, mapping.id),
      code('EK_JSON_TRANSFORM'),
    );
  } finally {
    await app.stop();
  }
  assert.throws(() => json.parse('null'), code('EK_RESOURCE_CLOSED'));
});
test('Native JSON workers capture immutable schema and mapping deployment catalogs without request provider calls', async () => {
  let calls = 0;
  const original = { type: 'string', minLength: 1 },
    mutable = {
      ...settings,
      schemas: { a: original },
      mappings: {
        ids: [],
        get() {
          calls++;
          throw Error('Never call');
        },
      },
    };
  const captured = capture(mutable);
  original.minLength = 100;
  const runtime = await Runtime.create(captured, new AbortController().signal, () => true);
  try {
    assert.equal((runtime.call('validate', 'ok', 'a') as { valid: boolean }).valid, true);
    assert.equal(calls, 0);
    assert.throws(() => runtime.call('validate', 'ok', 'unknown'), code('EK_JSON_SCHEMA'));
    assert.throws(() => runtime.call('transform', {}, 'unknown'), code('EK_JSON_TRANSFORM'));
  } finally {
    await runtime.close();
  }
});
test('Malformed native schemas, missing mapping contracts and invalid mapping grammar fail before capability readiness', async () => {
  for (const configured of [
    { ...settings, schemas: { input: { $ref: '#' }, output: {} } },
    { ...settings, schemas: { input: {}, output: { type: 'string' } } },
    {
      ...settings,
      mappings: {
        ids: [mapping.id],
        get: () => ({ ...mapping, fields: { x: { op: 'eval', code: 'process.env' } } }),
      },
    },
  ])
    await assert.rejects(
      Runtime.create(capture(configured as never), new AbortController().signal, () => true),
      (error: unknown) =>
        error instanceof KitError && ['EK_JSON_SCHEMA', 'EK_JSON_TRANSFORM'].includes(error.code),
    );
});
test('A real non-cooperative native regex validation is terminated at the wall deadline and cannot retain admission', async () => {
  const configured = capture({
    ...settings,
    schemas: { slow: { type: 'string', pattern: '^(a+)+$' } },
    mappings: { ids: [], get: () => null },
    policy: { ...settings.policy, timeoutMs: 1000 },
  });
  const runtime = await Runtime.create(configured, new AbortController().signal, () => true),
    started = performance.now();
  try {
    assert.throws(() => runtime.call('validate', 'a'.repeat(80) + '!', 'slow'), code('EK_TIMEOUT'));
    assert.ok(performance.now() - started < 3000);
    assert.throws(() => runtime.call('parse', 'null'), code('EK_BACKEND_UNAVAILABLE'));
  } finally {
    await runtime.close();
  }
  assert.ok(runtime.slots.every((slot) => slot.worker.threadId === -1));
  assert.ok(runtime.slots.every((slot) => slot.output.every((byte) => byte === 0)));
});
test('Actual worker failure, application cancellation and double close preserve owned cleanup and fail closed', async () => {
  const controller = new AbortController(),
    runtime = await Runtime.create(capture(settings), controller.signal, () => true);
  assert.ok(runtime.slots[0]!.worker.threadId > 0);
  await runtime.slots[0]!.worker.terminate();
  assert.throws(() => runtime.call('parse', 'null'), code('EK_BACKEND_UNAVAILABLE'));
  controller.abort();
  await runtime.close();
  await runtime.close();
  assert.throws(() => runtime.call('parse', 'null'), code('EK_RESOURCE_CLOSED'));
  const canceled = new AbortController();
  canceled.abort();
  await assert.rejects(
    Runtime.create(capture(settings), canceled.signal, () => true),
    code('EK_ABORTED'),
  );
});
test('Native request limits, option validation and readiness checks cannot be bypassed by manually constructed objects', async () => {
  let ready = false;
  const runtime = await Runtime.create(
    capture(settings),
    new AbortController().signal,
    () => ready,
  );
  try {
    assert.throws(() => runtime.call('parse', 'null'), code('EK_LIFECYCLE_STATE'));
    ready = true;
    for (const options of [
      null,
      { maxBytes: 0 },
      { maxBytes: 5000 },
      { maxDepth: 17 },
      { extra: true },
      { indentSpaces: 11 },
    ])
      assert.throws(
        () => runtime.call('parse', '{}', undefined, options as never),
        code('EK_CONFIG_INVALID'),
      );
    for (const value of ['x'.repeat(4097), '[1,', '"\\ud800"', '{"__proto__":1}'])
      assert.throws(() => runtime.call('parse', value), code('EK_JSON_PARSE'));
    assert.throws(
      () =>
        runtime.call('stringify', {
          get x() {
            throw Error('Never execute');
          },
        }),
      code('EK_JSON_PARSE'),
    );
    assert.equal(
      runtime.call('stringify', { x: 1 }, undefined, { indentSpaces: 2 }),
      '{\n  "x": 1\n}',
    );
  } finally {
    await runtime.close();
  }
});
test('Strict plugin configuration rejects missing policy, null, unknown settings and invalid positive deadlines before worker allocation', () => {
  for (const timeoutMs of [0, -1, 0.5, NaN, Infinity, 30001])
    assert.throws(
      () => dataJsonPlugin({ ...settings, policy: { ...settings.policy, timeoutMs } }),
      code('EK_CONFIG_INVALID'),
    );
  for (const configured of [
    null,
    { ...settings, extra: true },
    { ...settings, defaults: null },
    { ...settings, policy: {} },
    { ...settings, policy: { ...settings.policy, maxConcurrent: 0 } },
    { ...settings, mappings: { get: () => mapping } },
    {
      ...settings,
      mappings: {
        ids: [mapping.id],
        get() {
          throw Error('private-provider');
        },
      },
    },
  ])
    assert.throws(
      () => dataJsonPlugin(configured as never),
      (error: unknown) =>
        error instanceof KitError &&
        ['EK_CONFIG_INVALID', 'EK_JSON_TRANSFORM'].includes(error.code),
    );
});
test('Native workers reject inherited process preloads and expose only safe errors and real numeric observations', async () => {
  const previous = process.env.NODE_OPTIONS;
  process.env.NODE_OPTIONS = '--require=/private/unapproved-preload';
  const observations: unknown[] = [];
  let runtime: Runtime | undefined;
  try {
    runtime = await Runtime.create(
      capture(settings),
      new AbortController().signal,
      () => true,
      (value) => observations.push(value),
    );
    assert.equal(runtime.call('parse', '"private-json-sentinel"'), 'private-json-sentinel');
    assert.throws(
      () => runtime!.call('parse', '{"private-json-sentinel":'),
      (error: unknown) =>
        error instanceof KitError &&
        !JSON.stringify(error.toSafeJSON()).includes('private-json-sentinel'),
    );
    runtime.call('validate', { id: 2, active: 'true' }, 'input');
    runtime.call('transform', { id: '001', active: 'false' }, mapping.id);
    assert.equal(JSON.stringify(observations).includes('private-json-sentinel'), false);
    assert.ok(
      observations.some(
        (value) =>
          !!value &&
          typeof value === 'object' &&
          'heapBytes' in value &&
          typeof value.heapBytes === 'number' &&
          value.heapBytes > 0,
      ),
    );
  } finally {
    await runtime?.close();
    if (previous === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = previous;
  }
});

test('Independent native JSON instances cannot share mapping decisions or close another application worker', async () => {
  const first = await Runtime.create(
    capture({
      ...settings,
      mappings: {
        ids: ['fixed.v1'],
        get: () => ({
          ...mapping,
          id: 'fixed.v1',
          fields: { id: { op: 'literal', value: 'first' }, active: { op: 'literal', value: true } },
        }),
      },
    }),
    new AbortController().signal,
    () => true,
  );
  const second = await Runtime.create(
    capture({
      ...settings,
      mappings: {
        ids: ['fixed.v1'],
        get: () => ({
          ...mapping,
          id: 'fixed.v1',
          fields: {
            id: { op: 'literal', value: 'second' },
            active: { op: 'literal', value: false },
          },
        }),
      },
    }),
    new AbortController().signal,
    () => true,
  );
  try {
    const input = { id: '001', active: 'true' };
    assert.notEqual(first.slots[0]!.worker.threadId, second.slots[0]!.worker.threadId);
    assert.equal(
      (first.call('transform', input, 'fixed.v1') as Record<string, unknown>).id,
      'first',
    );
    assert.equal(
      (second.call('transform', input, 'fixed.v1') as Record<string, unknown>).id,
      'second',
    );
    await first.close();
    assert.equal(
      (second.call('transform', input, 'fixed.v1') as Record<string, unknown>).active,
      false,
    );
    assert.throws(() => second.call('parse', new Uint8Array([255])), code('EK_JSON_PARSE'));
  } finally {
    await first.close();
    await second.close();
  }
});

test('Retiring a real timed-out worker preserves only the finite remaining native capacity', async () => {
  const runtime = await Runtime.create(
    capture({
      ...settings,
      schemas: { slow: { type: 'string', pattern: '^(a+)+$' } },
      mappings: { ids: [], get: () => null },
      policy: { ...settings.policy, maxConcurrent: 2, timeoutMs: 1000 },
    }),
    new AbortController().signal,
    () => true,
  );
  try {
    assert.equal(new Set(runtime.slots.map((slot) => slot.worker.threadId)).size, 2);
    assert.throws(() => runtime.call('validate', 'a'.repeat(80) + '!', 'slow'), code('EK_TIMEOUT'));
    assert.equal(runtime.call('parse', 'true'), true);
    assert.equal(runtime.slots.filter((slot) => slot.retired).length, 1);
  } finally {
    await runtime.close();
  }
  assert.ok(runtime.slots.every((slot) => slot.worker.threadId === -1));
});

test('Duplicate public JSON plugin registration fails before a worker-backed capability can become ready', async () => {
  await assert.rejects(
    createApplication({
      service: { name: 'duplicate-json', version: '1.0.0', environment: 'test' },
      plugins: [dataJsonPlugin(settings), dataJsonPlugin(settings)],
    }),
    code('EK_PLUGIN_DUPLICATE'),
  );
});
