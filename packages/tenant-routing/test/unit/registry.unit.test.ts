// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import canonicalize from 'canonicalize';
import { KitError } from '@arkenivajs/core';
import { parseRegistry, registryContentChecksum, validateRegistry } from '../../dist/registry.js';

function fixture() {
  const value = {
    schemaVersion: '1.1.0' as const,
    revision: 'deployment-blue',
    activationGeneration: 1,
    activatedAt: '2026-01-01T00:00:00.000Z',
    contentChecksum: '',
    operations: [
      {
        id: 'orders.read',
        method: 'GET' as const,
        path: '/api/orders/:orderId',
        label: 'Read an order',
        schemas: { response: { type: 'object' } as Record<string, unknown> },
        policy: { requiredScopes: ['orders:read'] },
        maxConcurrency: 2,
        maxBodyBytes: 1024,
        maxResponseBytes: 4096,
        timeoutMs: 1000,
      },
    ],
    implementations: [{ id: 'local-orders', kind: 'handler' as const, handlerKey: 'read-order' }],
    bindings: [
      {
        tenantId: 'north',
        operationId: 'orders.read',
        implementationId: 'local-orders',
        enabled: true,
      },
    ],
  };
  value.contentChecksum = registryContentChecksum(value);
  return value;
}
const invalid = (run: () => unknown) =>
  assert.throws(run, (error: unknown) => {
    assert.ok(error instanceof KitError);
    assert.equal(error.code, 'EK_TROUTE_REGISTRY');
    assert.equal(error.message, 'Invalid tenant routing registry');
    return true;
  });
function signed(change: (value: ReturnType<typeof fixture>) => void) {
  const value = fixture();
  change(value);
  value.contentChecksum = registryContentChecksum(value);
  return value;
}

test('Registry parsing returns an independent deeply immutable content snapshot', () => {
  const source = fixture(),
    snapshot = validateRegistry(source),
    parsed = parseRegistry(JSON.stringify(source, null, 2));
  assert.equal(JSON.stringify(snapshot), JSON.stringify(source));
  assert.equal(JSON.stringify(parsed), JSON.stringify(source));
  source.operations[0]!.label = 'Changed after publication';
  assert.equal(snapshot.operations[0]!.label, 'Read an order');
  for (const value of [snapshot, snapshot.operations, snapshot.operations[0]!.schemas.response])
    assert.ok(Object.isFrozen(value));
  assert.throws(() => Object.assign(snapshot.operations[0]!, { label: 'Changed' }), TypeError);
});

test('JCS follows RFC 8785 numeric serialization and UTF-16 property ordering', () => {
  // Public RFC 8785 sections 3.2.2 and 3.2.3: https://www.rfc-editor.org/rfc/rfc8785.
  assert.equal(
    canonicalize({ numbers: JSON.parse('[333333333.33333329,1e30,4.5,2e-3,1e-27]') }),
    '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}',
  );
  assert.equal(
    canonicalize({ '\ufffd': 3, '\u20ac': 1, '\ud83d\ude00': 2 }),
    '{"€":1,"😀":2,"�":3}',
  );
  const source = fixture();
  const body =
    '{"bindings":[{"enabled":true,"implementationId":"local-orders","operationId":"orders.read","tenantId":"north"}],"implementations":[{"handlerKey":"read-order","id":"local-orders","kind":"handler"}],"operations":[{"id":"orders.read","label":"Read an order","maxBodyBytes":1024,"maxConcurrency":2,"maxResponseBytes":4096,"method":"GET","path":"/api/orders/:orderId","policy":{"requiredScopes":["orders:read"]},"schemas":{"response":{"type":"object"}},"timeoutMs":1000}],"schemaVersion":"1.1.0"}';
  assert.equal(source.contentChecksum, 'sha256:' + createHash('sha256').update(body).digest('hex'));
});

test('Checksums ignore activation metadata and property order but preserve every array order', () => {
  const source = fixture();
  assert.equal(
    registryContentChecksum({ ...source, operations: source.operations }),
    source.contentChecksum,
  );
  const reactivated = { ...source, revision: 'later', activationGeneration: 9 };
  assert.equal(registryContentChecksum(reactivated), source.contentChecksum);
  const reordered = JSON.parse(JSON.stringify(source)) as ReturnType<typeof fixture>;
  reordered.operations[0]!.policy.requiredScopes.push('orders:audit');
  const before = registryContentChecksum(reordered);
  reordered.operations[0]!.policy.requiredScopes.reverse();
  assert.notEqual(registryContentChecksum(reordered), before);
  source.operations[0]!.label = 'Tampered configuration';
  invalid(() => validateRegistry(source));
});

test('Raw registry syntax rejects duplicate decoded keys, comments, trailing content and malformed UTF-8 data', () => {
  const source = JSON.stringify(fixture());
  for (const text of [
    source.replace('"revision":', '"revision":"first","revision":'),
    source.replace('"revision":', '"\\u0072evision":"first","revision":'),
    source.replace('"type":"object"', '"type":"object","type":"object"'),
    source.replace('{', '{/* comment */'),
    source.replace('{', '{// comment\n'),
    source.slice(0, -1) + ',}',
    source + '{}',
    source.slice(0, -1),
    '',
    ' ',
    '[',
    '}',
    '{"x":"\\ud800"}',
    source.replace('Read an order', '\ud800'),
    '['.repeat(65) + '0' + ']'.repeat(65),
    source.replace('"activationGeneration":1', '"activationGeneration":1e999'),
  ])
    invalid(() => parseRegistry(text));
});

test('Both text and object APIs enforce explicit byte bounds including multibyte and escaped strings', () => {
  const source = fixture(),
    text = JSON.stringify(source);
  assert.equal(parseRegistry(text, Buffer.byteLength(text)).revision, source.revision);
  invalid(() => parseRegistry(text, Buffer.byteLength(text) - 1));
  assert.equal(validateRegistry(source, Buffer.byteLength(text)).revision, source.revision);
  invalid(() => validateRegistry(source, Buffer.byteLength(text) - 1));
  for (const limit of [0, -1, 1.5, Infinity, Number.MAX_SAFE_INTEGER + 1]) {
    invalid(() => parseRegistry(text, limit));
    invalid(() => validateRegistry(source, limit));
  }
  const unicode = signed((value) => {
    value.operations[0]!.label = '€'.repeat(100);
  });
  invalid(() => parseRegistry(JSON.stringify(unicode), JSON.stringify(unicode).length));
  const escaped = fixture();
  escaped.operations[0]!.schemas.response.const = '\u0000'.repeat(100);
  escaped.contentChecksum = registryContentChecksum(escaped);
  const size = Buffer.byteLength(JSON.stringify(escaped));
  assert.equal(validateRegistry(escaped, size).revision, escaped.revision);
  invalid(() => validateRegistry(escaped, size - 1));
});

test('Executable objects, getters, proxies and non-JSON values fail without executing supplied code', () => {
  let effects = 0;
  const getter = Object.defineProperty({}, 'value', {
    enumerable: true,
    get() {
      effects++;
      return 1;
    },
  });
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        effects++;
        throw new Error('Private data');
      },
    },
  );
  const cycle: Record<string, unknown> = {};
  cycle.self = cycle;
  const toJSON = {
    toJSON() {
      effects++;
      return {};
    },
  };
  const sparse = new Array(2);
  const extra = Object.assign([1], { other: 2 });
  const hidden = Object.defineProperty({}, 'hidden', { value: 1 });
  for (const value of [
    undefined,
    NaN,
    Infinity,
    -Infinity,
    1n,
    Symbol('private'),
    () => {
      effects++;
    },
    getter,
    proxy,
    cycle,
    toJSON,
    sparse,
    extra,
    hidden,
    new Date(),
    Object.assign({}, { [Symbol('private')]: 1 }),
    Object.assign({}, { '\ud800': 1 }),
  ]) {
    const source = fixture();
    source.operations[0]!.schemas.response.const = value;
    invalid(() => validateRegistry(source));
  }
  assert.equal(effects, 0);
});

test('Structural registry rules reject old schemas, unsafe bounds and unrecognized fields', () => {
  const changes: ((value: ReturnType<typeof fixture>) => void)[] = [
    (v) => Object.assign(v, { schemaVersion: '1.0.0' }),
    (v) => Object.assign(v, { extra: true }),
    (v) => Object.assign(v, { revision: '' }),
    (v) => Object.assign(v, { activatedAt: '2026-01-01T01:00:00+01:00' }),
    (v) => Object.assign(v, { activatedAt: 'invalid' }),
    (v) => Object.assign(v, { activationGeneration: Number.MAX_SAFE_INTEGER + 1 }),
    (v) => Object.assign(v.operations[0]!, { maxConcurrency: 0 }),
    (v) => Object.assign(v.operations[0]!, { maxConcurrency: 10001 }),
    (v) => Object.assign(v.operations[0]!, { maxConcurrency: 1.5 }),
    (v) => {
      delete (v.operations[0] as Partial<(typeof v.operations)[0]>).maxConcurrency;
    },
    (v) => Object.assign(v.operations[0]!, { timeoutMs: 120001 }),
    (v) => Object.assign(v.operations[0]!, { maxBodyBytes: 10485761 }),
    (v) => Object.assign(v.operations[0]!, { maxResponseBytes: 0 }),
    (v) => Object.assign(v.operations[0]!, { method: 'TRACE' }),
    (v) => Object.assign(v.operations[0]!.policy, { requiredScopes: ['same', 'same'] }),
    (v) => Object.assign(v.bindings[0]!, { enabled: 'true' }),
  ];
  for (const change of changes) invalid(() => validateRegistry(signed(change)));
  const maximal = signed((v) => {
    v.activationGeneration = Number.MAX_SAFE_INTEGER;
    v.operations[0]!.maxConcurrency = 10000;
    v.operations[0]!.maxBodyBytes = 10485760;
    v.operations[0]!.maxResponseBytes = 10485760;
    v.operations[0]!.timeoutMs = 120000;
  });
  assert.equal(validateRegistry(maximal).activationGeneration, Number.MAX_SAFE_INTEGER);
});

test('Referential integrity and route normalization reject ambiguous or unsafe definitions', () => {
  const changes: ((value: ReturnType<typeof fixture>) => void)[] = [
    (v) => {
      v.operations.push(structuredClone(v.operations[0]!));
    },
    (v) => {
      v.implementations.push(structuredClone(v.implementations[0]!));
    },
    (v) => {
      v.bindings.push(structuredClone(v.bindings[0]!));
    },
    (v) => {
      v.bindings[0]!.operationId = 'missing';
    },
    (v) => {
      v.bindings[0]!.implementationId = 'missing';
    },
    (v) => {
      v.operations.push({
        ...structuredClone(v.operations[0]!),
        id: 'orders.other',
        path: '/api/orders/:different',
      });
    },
    (v) => {
      v.operations[0]!.path = '/api/:id/:id';
    },
    (v) => {
      v.operations[0]!.path = '/api/../private';
    },
    (v) => {
      v.operations[0]!.path = '/api//orders';
    },
    (v) => {
      v.operations[0]!.path = '/api/orders/';
    },
    (v) => {
      v.operations[0]!.path = '/api/orders/:bad-name';
    },
    (v) => {
      v.operations[0]!.label = 'secret\nvalue';
    },
  ];
  for (const change of changes) invalid(() => validateRegistry(signed(change)));
});

test('HTTP implementations preserve the legacy response alias without permitting collisions or unsafe paths', () => {
  for (const patch of [
    { upstreamPath: '//private' },
    { upstreamPath: '/x/../private' },
    { upstreamPath: '/%2e%2e/private' },
    { upstreamPath: 'https://example.test/' },
    { transformerKey: 'legacy', responseTransformerKey: 'current' },
  ]) {
    const value = fixture();
    Object.assign(value.implementations[0]!, { kind: 'http', handlerKey: undefined });
    delete (value.implementations[0] as { handlerKey?: string }).handlerKey;
    Object.assign(value.implementations[0]!, {
      upstreamKey: 'orders',
      upstreamPath: '/',
      method: 'GET',
      ...patch,
    });
    value.contentChecksum = registryContentChecksum(value);
    invalid(() => validateRegistry(value));
  }
  for (const alias of ['transformerKey', 'responseTransformerKey']) {
    const value = fixture();
    delete (value.implementations[0] as { handlerKey?: string }).handlerKey;
    Object.assign(value.implementations[0]!, {
      kind: 'http',
      upstreamKey: 'orders',
      upstreamPath: '/',
      method: 'GET',
      requestTransformerKey: 'request',
      [alias]: 'response',
    });
    value.contentChecksum = registryContentChecksum(value);
    assert.equal(validateRegistry(value).implementations[0]!.kind, 'http');
  }
});

test('Operation schemas reject unknown keywords, unresolved references, asynchronous and nested remote validators', () => {
  for (const schema of [
    { type: 'unknown' },
    { execute: 'import-private' },
    { $ref: 'https://example.test/schema' },
    { $ref: '#/$defs/missing' },
    { $async: true, type: 'object' },
    { properties: { nested: { $ref: 'file:///private' } } },
    { allOf: [{ $ref: 'https://example.test/schema' }] },
    { additionalProperties: { $dynamicRef: 'https://example.test/schema' } },
    { dependencies: { first: { $ref: 'https://example.test/schema' } } },
    { $defs: { hidden: { $ref: 'https://example.test/schema' } } },
  ])
    invalid(() =>
      validateRegistry(
        signed((v) => {
          v.operations[0]!.schemas.response = schema;
        }),
      ),
    );
  const local = signed((v) => {
    v.operations[0]!.schemas.response = {
      type: 'object',
      properties: { id: { $ref: '#/$defs/id' } },
      $defs: { id: { type: 'string' } },
      const: { $ref: 'https://example.test/literal-not-a-schema' },
    };
  });
  assert.equal(validateRegistry(local).operations.length, 1);
});
