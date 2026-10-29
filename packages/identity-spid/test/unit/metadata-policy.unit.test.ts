// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyMetadataPolicies } from '../../dist/metadata-policy.js';

const apply = (metadata: unknown, policies: readonly unknown[]) =>
  applyMetadataPolicies(metadata, policies, 65536);
const plain = (value: unknown): unknown => JSON.parse(JSON.stringify(value));
const one = (rule: unknown) => ({ openid_provider: { policy_parameter: rule } });
const fail = (rule: unknown, value: unknown = 'untrusted') =>
  assert.throws(() => apply({ openid_provider: { policy_parameter: value } }, [one(rule)]), {
    code: 'EK_EID_FEDERATION',
  });

test('Upper and lower federation policies merge before standard ordered application', () => {
  const metadata = {
    openid_relying_party: {
      token_endpoint_auth_method: 'private_key_jwt',
      contacts: ['owner@example.test'],
    },
  };
  const root = {
    openid_relying_party: {
      grant_types: {
        default: ['authorization_code'],
        superset_of: ['authorization_code'],
        subset_of: ['authorization_code', 'refresh_token'],
      },
      token_endpoint_auth_method: {
        one_of: ['private_key_jwt', 'tls_client_auth'],
        essential: true,
      },
      contacts: { add: ['security@example.test'] },
    },
  };
  const lower = {
    openid_relying_party: {
      grant_types: { subset_of: ['authorization_code'] },
      token_endpoint_auth_method: { one_of: ['private_key_jwt'], essential: false },
      contacts: { add: ['security@example.test', 'support@example.test'] },
    },
  };
  assert.deepEqual(plain(apply(metadata, [root, lower])), {
    openid_relying_party: {
      token_endpoint_auth_method: 'private_key_jwt',
      contacts: ['owner@example.test', 'security@example.test', 'support@example.test'],
      grant_types: ['authorization_code'],
    },
  });
  assert.deepEqual(metadata.openid_relying_party.contacts, ['owner@example.test']);
});
test('Subset transforms metadata and can preserve an essential empty set', () => {
  assert.deepEqual(
    plain(
      apply({ openid_provider: { policy_parameter: ['code', 'implicit'] } }, [
        one({ subset_of: ['code'], essential: true }),
      ]),
    ),
    { openid_provider: { policy_parameter: ['code'] } },
  );
  assert.deepEqual(
    plain(
      apply({ openid_provider: { policy_parameter: ['implicit'] } }, [
        one({ subset_of: ['code'], essential: true }),
      ]),
    ),
    { openid_provider: { policy_parameter: [] } },
  );
});
test('Value removal, defaults and essential presence use the required application order', () => {
  assert.deepEqual(
    plain(
      apply({ openid_provider: { policy_parameter: 'old' } }, [
        one({ value: null, essential: false }),
      ]),
    ),
    { openid_provider: {} },
  );
  assert.deepEqual(plain(apply({}, [one({ default: 'RS256', essential: true })])), {
    openid_provider: { policy_parameter: 'RS256' },
  });
  assert.deepEqual(plain(apply({}, [one({ value: 'RS512', default: 'RS256' })])), {
    openid_provider: { policy_parameter: 'RS512' },
  });
  assert.deepEqual(plain(apply({}, [one({ subset_of: ['code'], essential: false })])), {});
  assert.throws(() => apply({}, [one({ essential: true }), one({ essential: false })]), {
    code: 'EK_EID_FEDERATION',
  });
});
test('Conflicting upper/lower values, defaults and one-of restrictions invalidate the chain', () => {
  for (const [upper, lower] of [
    [{ value: 'a' }, { value: 'b' }],
    [{ default: 'a' }, { default: 'b' }],
    [{ one_of: ['a'] }, { one_of: ['b'] }],
  ])
    assert.throws(() => apply({}, [one(upper), one(lower)]), { code: 'EK_EID_FEDERATION' });
});
test('A lower policy cannot remove required values or weaken an essential upper policy', () => {
  assert.throws(() => apply({}, [one({ add: ['code'] }), one({ subset_of: ['refresh_token'] })]), {
    code: 'EK_EID_FEDERATION',
  });
  assert.throws(
    () => apply({}, [one({ superset_of: ['code'] }), one({ subset_of: ['refresh_token'] })]),
    { code: 'EK_EID_FEDERATION' },
  );
  fail({ superset_of: ['code'], essential: true }, ['refresh_token']);
});
test('Policy combinations are validated even when the metadata parameter is absent', () => {
  for (const rule of [
    { one_of: ['a'], add: ['a'] },
    { one_of: ['a'], subset_of: ['a'] },
    { one_of: ['a'], superset_of: ['a'] },
    { value: null, default: 'a' },
    { value: null, essential: true },
    { value: ['a'], add: ['b'] },
    { value: ['a'], subset_of: ['b'] },
    { value: ['a'], superset_of: ['b'] },
    { value: 'a', one_of: ['b'] },
    { ignore_security: true },
    { essential: 'true' },
    { default: null },
    { one_of: [] },
  ])
    assert.throws(() => apply({}, [one(rule)]), { code: 'EK_EID_FEDERATION' });
});
test('Object-valued Italian JWKS policy compares normalized JSON without depending on property order', () => {
  const first = { keys: [{ kid: 'public', kty: 'RSA' }] },
    second = { keys: [{ kty: 'RSA', kid: 'public' }] };
  const result = apply({}, [
    { openid_provider: { jwks: { value: first, essential: true } } },
    { openid_provider: { jwks: { value: second } } },
  ]);
  assert.deepEqual(plain(result), { openid_provider: { jwks: first } });
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen((result.openid_provider as { jwks: object }).jwks));
});
test('Entity-type policies remain isolated and do not rewrite a different role', () => {
  assert.deepEqual(
    plain(
      apply(
        {
          openid_provider: { token_endpoint_auth_method: 'provider-value' },
          openid_relying_party: { token_endpoint_auth_method: 'client-value' },
        },
        [{ openid_relying_party: { token_endpoint_auth_method: { value: 'private_key_jwt' } } }],
      ),
    ),
    {
      openid_provider: { token_endpoint_auth_method: 'provider-value' },
      openid_relying_party: { token_endpoint_auth_method: 'private_key_jwt' },
    },
  );
});
test('Set comparison supports finite numbers and objects without permissive type coercion', () => {
  assert.deepEqual(
    plain(
      apply({ openid_provider: { policy_parameter: [{ a: 1 }, { a: 2 }] } }, [
        one({ subset_of: [{ a: 2 }], superset_of: [{ a: 2 }] }),
      ]),
    ),
    { openid_provider: { policy_parameter: [{ a: 2 }] } },
  );
  fail({ one_of: [1, 2] }, '1');
  fail({ subset_of: [true] }, [true]);
  fail({ subset_of: [['nested']] }, [['nested']]);
  fail({ subset_of: ['a', 'a'] }, ['a']);
  assert.deepEqual(plain(apply({}, [one({ value: -0 }), one({ value: 0 })])), {
    openid_provider: { policy_parameter: 0 },
  });
});
test('Executable inputs and prototype-like policy keys cannot run code or mutate shared prototypes', () => {
  let effects = 0;
  const metadata = {
    get openid_provider() {
      effects++;
      throw new Error('Executable metadata');
    },
  };
  assert.throws(() => apply(metadata, []), { code: 'EK_EID_FEDERATION' });
  assert.throws(
    () =>
      apply(
        new Proxy(
          {},
          {
            ownKeys() {
              effects++;
              return [];
            },
          },
        ),
        [],
      ),
    { code: 'EK_EID_FEDERATION' },
  );
  assert.throws(() => apply({}, [JSON.parse('{"__proto__":{"polluted":true}}')]), {
    code: 'EK_EID_FEDERATION',
  });
  assert.equal(effects, 0);
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});
test('Metadata depth, structure, finite-number and byte limits fail before returning policy output', () => {
  let deep: unknown = {};
  for (let depth = 0; depth < 20; depth++) deep = { nested: deep };
  for (const metadata of [
    deep,
    { openid_provider: null },
    { openid_provider: { value: NaN } },
    { openid_provider: { value: 'x'.repeat(65536) } },
  ])
    assert.throws(() => apply(metadata, []), { code: 'EK_EID_FEDERATION' });
  assert.throws(() => applyMetadataPolicies({}, [], 0), { code: 'EK_EID_FEDERATION' });
});
