// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';

const valueKey = Symbol('core-comparison.value'),
  serviceKey = Symbol('core-comparison.service'),
  missing = Symbol('core-comparison.missing');
export const lookupsPerBatch = 256;
const lifecycle = (error) => error instanceof KitError && error.code === 'EK_LIFECYCLE_STATE';

export function nativeCore(fixture) {
  const value = Object.freeze({ marker: fixture.marker, count: 7 }),
    registry = new Map([[valueKey, value]]);
  return {
    required: () => registry.get(valueKey),
    optional: () => registry.get(valueKey),
    optionalMissing: () => registry.get(missing),
    requiredMissing() {
      if (!registry.has(missing)) throw new Error('The native comparison capability is absent');
      return registry.get(missing);
    },
    close: () => registry.clear(),
  };
}

/** Resolve through the actual application; no observation is added to the core lookup path. */
export function frameworkCore(fixture) {
  let app;
  const value = Object.freeze({ marker: fixture.marker, count: 7 });
  return {
    plugin: {
      id: 'core-comparison',
      version: '1.0.0',
      capabilities: new Set(['core-comparison']),
      init(context) {
        context.provide(valueKey, value);
        context.provide(serviceKey, {
          required: () => app.resolve(valueKey),
          optional: () => app.tryResolve(valueKey),
          optionalMissing: () => app.tryResolve(missing),
          requiredMissing: () => app.resolve(missing),
        });
      },
      close() {},
    },
    key: serviceKey,
    configure(application) {
      app = application;
      assert.throws(() => app.resolve(valueKey), lifecycle);
      assert.throws(() => app.tryResolve(valueKey), lifecycle);
    },
    dispose() {
      assert.equal(app.state, 'CLOSED');
      assert.throws(() => app.resolve(valueKey), lifecycle);
      assert.throws(() => app.tryResolve(valueKey), lifecycle);
    },
  };
}

export function verifyCore(service, fixture) {
  const value = service.required();
  assert.equal(value.marker, fixture.marker);
  assert.equal(value.count, 7);
  assert.equal(Object.isFrozen(value), true);
  for (let index = 0; index < 128; index++) {
    assert.equal(service.required(), value);
    assert.equal(service.optional(), value);
  }
  assert.equal(service.optionalMissing(), undefined);
  assert.throws(() => service.requiredMissing());
  return {
    lookupPairsVerified: 128,
    identityPreserved: true,
    immutableValue: true,
    optionalMissing: true,
    requiredMissingRejected: true,
  };
}

export function coreWorkload(service) {
  const batch = (lookup) => () => {
    let consumed = 0;
    for (let index = 0; index < lookupsPerBatch; index++) consumed += lookup().count;
    assert.equal(consumed, lookupsPerBatch * 7);
    return consumed;
  };
  return { 'resolve-256': batch(service.required), 'try-resolve-256': batch(service.optional) };
}
