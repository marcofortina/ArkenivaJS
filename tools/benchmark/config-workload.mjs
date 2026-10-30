// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import Ajv from 'ajv';
import { parseDocument } from 'yaml';

export const configFixture = Object.freeze({
  marker: 'owned-config-corpus-value',
  yamlText: 'count: 2\nenabled: true\n',
  environmentValue: '3',
});
export const configSchema = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: ['count', 'label', 'enabled', 'nullable'],
  properties: {
    count: { type: 'integer', minimum: 0, maximum: 100 },
    label: { type: 'string' },
    enabled: { type: 'boolean' },
    nullable: { type: ['string', 'null'] },
  },
});
export const configOptions = (fixture = configFixture) => ({
  workspace: process.cwd(),
  schema: configSchema,
  defaults: { count: 1, label: fixture.marker, enabled: false, nullable: null },
  yamlText: fixture.yamlText,
  environment: { ARKENIVAJS_BENCH_COUNT: fixture.environmentValue },
  environmentFields: { ARKENIVAJS_BENCH_COUNT: { path: 'count', type: 'integer' } },
  runtime: { count: 4 },
  dynamicPaths: ['count'],
  onDiagnostic: () => undefined,
});

/** Bare YAML/Ajv and flat values serve only this fixed, nonsecret valid corpus. */
export function nativeConfig(fixture = configFixture) {
  const options = configOptions(fixture),
    validate = new Ajv({ strict: true, allErrors: true }).compile(configSchema);
  const yaml = parseDocument(fixture.yamlText, {
    uniqueKeys: true,
    customTags: [],
    strict: true,
  }).toJS({ maxAliasCount: 0 });
  let current = Object.freeze({
    ...options.defaults,
    ...yaml,
    count: Number(fixture.environmentValue),
    ...options.runtime,
  });
  if (!validate(current)) throw new Error('The native configuration corpus is invalid');
  return {
    get: (key) => current[key],
    has: (key) => Object.hasOwn(current, key),
    require(key) {
      const value = current[key];
      if (value === undefined || value === null)
        throw new Error('The configuration path is missing');
      return value;
    },
    snapshot: () => current,
    async reload(updates) {
      const next = { ...current, ...updates };
      if (!validate(next)) throw new Error('The native reload is invalid');
      current = Object.freeze(next);
    },
  };
}

export async function verifyConfig(service, fixture = configFixture) {
  assert.equal(service.get('count'), 4);
  assert.equal(service.require('label'), fixture.marker);
  assert.equal(service.get('enabled'), true);
  assert.equal(service.has('nullable'), true);
  assert.equal(service.get('nullable'), null);
  assert.equal(service.get('missing'), undefined);
  assert.throws(() => service.require('missing'));
  assert.throws(() => service.require('nullable'));
  const before = service.snapshot();
  assert.equal(Object.isFrozen(before), true);
  await service.reload({ count: 5 });
  assert.equal(service.get('count'), 5);
  assert.equal(before.count, 4);
  await assert.rejects(service.reload({ count: -1 }));
  assert.equal(service.get('count'), 5);
  await service.reload({ count: 4 });
  return {
    checkedCases: 8,
    precedenceVerified: true,
    failedReloadPreservedState: true,
    priorSnapshotImmutable: true,
  };
}

export function configWorkload(service) {
  let next = 1;
  return {
    get: () => service.get('count'),
    require: () => service.require('count'),
    has: () => service.has('nullable'),
    snapshot: () => service.snapshot(),
    reload: () => service.reload({ count: (next = 3 - next) }),
  };
}
