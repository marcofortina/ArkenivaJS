// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';

const inputId = 'comparison.input.v1',
  outputId = 'comparison.output.v1',
  mappingId = 'comparison.projection.v1';
const plain = (value) => JSON.parse(JSON.stringify(value));
export const jsonIterations = 100;
export const jsonWarmupIterations = 20;
const workloads = new WeakMap();

function corpus(fixture) {
  return {
    id: '001',
    profile: { label: fixture.marker },
    enabled: 'true',
    aliases: [{ value: '007' }, { value: '008' }],
    nullable: null,
  };
}

function projection(fixture) {
  return {
    code: '001',
    display: 'Name:' + fixture.marker,
    active: true,
    aliases: ['007', '008'],
    nullable: null,
    fallback: 'fallback',
  };
}

export function jsonSettings() {
  const mapping = {
    schemaVersion: '1.0.0',
    id: mappingId,
    inputSchemaId: inputId,
    outputSchemaId: outputId,
    fields: {
      code: { op: 'copy', path: '/id', required: true },
      display: {
        op: 'concat',
        args: [
          { op: 'literal', value: 'Name' },
          { op: 'copy', path: '/profile/label', required: true },
        ],
        separator: ':',
      },
      active: { op: 'to-boolean', value: { op: 'copy', path: '/enabled', required: true } },
      aliases: {
        op: 'array-map',
        path: '/aliases',
        item: { op: 'copy', path: '/value', required: true },
        maxItems: 4,
      },
      nullable: { op: 'copy', path: '/nullable', required: true },
      fallback: {
        op: 'coalesce',
        args: [
          { op: 'copy', path: '/missing' },
          { op: 'copy', path: '/nullable' },
          { op: 'literal', value: 'fallback' },
        ],
      },
      omitted: { op: 'copy', path: '/missing' },
    },
    limits: { maxDepth: 8, maxNodes: 64, maxArrayItems: 16, maxOutputBytes: 4096 },
  };
  return {
    defaults: { maxBytes: 4096, maxDepth: 16 },
    schemas: {
      [inputId]: {
        type: 'object',
        additionalProperties: false,
        required: ['id', 'profile', 'enabled', 'aliases', 'nullable'],
        properties: {
          id: { type: 'string', pattern: '^[0-9]{3}$' },
          profile: {
            type: 'object',
            additionalProperties: false,
            required: ['label'],
            properties: { label: { type: 'string', maxLength: 80 } },
          },
          enabled: { type: 'string', enum: ['true', 'false'] },
          aliases: {
            type: 'array',
            maxItems: 4,
            items: {
              type: 'object',
              additionalProperties: false,
              required: ['value'],
              properties: { value: { type: 'string' } },
            },
          },
          nullable: { type: 'null' },
        },
      },
      [outputId]: {
        type: 'object',
        additionalProperties: false,
        required: ['code', 'display', 'active', 'aliases', 'nullable', 'fallback'],
        properties: {
          code: { type: 'string' },
          display: { type: 'string' },
          active: { type: 'boolean' },
          aliases: { type: 'array', items: { type: 'string' } },
          nullable: { type: 'null' },
          fallback: { type: 'string' },
          omitted: { type: 'string' },
        },
      },
    },
    mappings: { ids: [mappingId], get: (id) => (id === mappingId ? mapping : null) },
    policy: { maxConcurrent: 1, timeoutMs: 3000, maxInputBytes: 4096, maxOutputBytes: 8192 },
  };
}

/** A fixed native projection matches only this valid corpus, without implementing the mapping grammar. */
export function nativeJson() {
  const settings = jsonSettings();
  const compiler = new Ajv2020({
    strictSchema: true,
    strictNumbers: true,
    strictTypes: false,
    strictRequired: false,
    allErrors: false,
    ownProperties: true,
    coerceTypes: false,
    useDefaults: false,
    removeAdditional: false,
    messages: false,
    logger: false,
  });
  const validators = new Map(
    Object.entries(settings.schemas).map(([id, schema]) => [id, compiler.compile(schema)]),
  );
  function validate(value, id) {
    const check = validators.get(id);
    assert.ok(check);
    return check(value)
      ? { valid: true, value, errors: [] }
      : {
          valid: false,
          errors: check.errors.map((error) => ({ path: error.instancePath, code: error.keyword })),
        };
  }
  return {
    parse: (text) => JSON.parse(text),
    stringify: (value, options) => JSON.stringify(value, null, options?.indentSpaces ?? 0),
    validate,
    transform(value, id) {
      assert.equal(id, mappingId);
      assert.equal(validate(value, inputId).valid, true);
      const result = {
        code: value.id,
        display: 'Name:' + value.profile.label,
        active: value.enabled === 'true',
        aliases: value.aliases.map((item) => item.value),
        nullable: value.nullable,
        fallback: 'fallback',
      };
      assert.equal(validate(result, outputId).valid, true);
      return result;
    },
  };
}

export function verifyJson(service, fixture) {
  const input = corpus(fixture);
  const source = JSON.stringify(input),
    parsed = service.parse(source);
  assert.deepEqual(plain(parsed), input);
  const valid = service.validate(parsed, inputId);
  assert.equal(valid.valid, true);
  assert.deepEqual(plain(valid.value), input);
  const invalid = service.validate({ ...input, id: 'bad' }, inputId);
  assert.equal(invalid.valid, false);
  assert.deepEqual([...new Set(invalid.errors.map((error) => error.path))], ['/id']);
  const transformed = service.transform(parsed, mappingId);
  const expected = projection(fixture);
  assert.deepEqual(plain(transformed), expected);
  assert.equal(Object.hasOwn(transformed, 'omitted'), false);
  assert.equal(Object.hasOwn(transformed, 'nullable'), true);
  assert.equal(service.stringify(transformed), JSON.stringify(expected));
  assert.equal(
    service.stringify(transformed, { indentSpaces: 2 }),
    JSON.stringify(expected, null, 2),
  );
  assert.equal(service.stringify(parsed), source);
  const empty = { ...input, enabled: 'false', aliases: [] };
  assert.deepEqual(plain(service.transform(empty, mappingId)), {
    ...expected,
    active: false,
    aliases: [],
  });
  return {
    operationsVerified: 4,
    schemaRejectionPathVerified: true,
    arrayOrderAndEmptyPreserved: true,
    missingOmittedAndNullPreserved: true,
    explicitScalarConversionVerified: true,
    inputUnchanged: true,
    deterministicSerializationVerified: true,
  };
}

/** Keep the finite identical corpus and completed results outside the public service. */
export function jsonWorkload(service, fixture) {
  assert.equal(workloads.has(service), false);
  const input = corpus(fixture),
    source = JSON.stringify(input),
    results = { parse: [], stringify: [], validate: [], transform: [] };
  workloads.set(service, { input, source, results });
  const capture = (operation, value) => {
    assert.ok(results[operation].length < jsonIterations + jsonWarmupIterations);
    results[operation].push(value);
    return value;
  };
  return {
    parse: () => capture('parse', service.parse(source)),
    stringify: () => capture('stringify', service.stringify(input)),
    validate: () => capture('validate', service.validate(input, inputId)),
    transform: () => capture('transform', service.transform(input, mappingId)),
  };
}

/** Reconcile every actual callback and validate all outputs after the measurement window. */
export function completeJsonWorkload(service, { fixture, measure, records }) {
  const state = workloads.get(service);
  try {
    if (!measure) {
      assert.equal(state, undefined);
      assert.deepEqual(records, []);
      return { sampledOperations: 0, warmupOperations: 0, checkedResults: 0 };
    }
    assert.ok(state);
    assert.deepEqual(
      records.map((record) => record.operation),
      Object.keys(state.results),
    );
    const input = corpus(fixture),
      expected = projection(fixture);
    assert.equal(JSON.stringify(state.input), state.source);
    assert.deepEqual(state.input, input);
    for (const record of records) {
      assert.equal(record.sampleCount, jsonIterations);
      assert.equal(record.warmupIterations, jsonWarmupIterations);
      const results = state.results[record.operation];
      assert.equal(results.length, record.sampleCount + record.warmupIterations);
      for (const result of results) {
        if (record.operation === 'stringify') assert.equal(result, state.source);
        else if (record.operation === 'validate') {
          assert.equal(result.valid, true);
          assert.deepEqual(plain(result.value), input);
          assert.deepEqual(plain(result.errors), []);
        } else assert.deepEqual(plain(result), record.operation === 'parse' ? input : expected);
      }
    }
    return {
      sampledOperations: 4 * jsonIterations,
      warmupOperations: 4 * jsonWarmupIterations,
      checkedResults: 4 * (jsonIterations + jsonWarmupIterations),
      inputUnchanged: true,
      exactProjectionVerified: true,
      boundedRetainedResults: true,
    };
  } finally {
    workloads.delete(service);
  }
}
