// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLdapService } from '../../dist/index.js';
import { capture } from '../../dist/settings.js';
import type { LdapSettings } from '../../dist/index.js';

function settings(): LdapSettings {
  return {
    url: 'ldaps://127.0.0.1:16389',
    baseDn: 'ou=people,dc=fixture,dc=invalid',
    groupSearchBaseDn: 'ou=groups,dc=fixture,dc=invalid',
    userFilterTemplate: '(uid={username})',
    serviceBindDnRef: 'fixture://bind-dn',
    serviceBindPasswordRef: 'fixture://bind-password',
    environment: 'test',
    secretProvider: {
      async get() {
        throw new Error('The original disposable provider is unavailable');
      },
    },
  };
}

test('LDAP secret callable metadata cannot replace or invoke the configured unavailable provider during capture', async () => {
  const input = settings();
  let redirected = 0;
  Object.defineProperty(input.secretProvider.get, 'bind', {
    value: () => async () => {
      redirected++;
      return { bytes: Buffer.from('unapproved'), keyVersion: 'fixture' };
    },
  });
  const captured = capture(input);
  await assert.rejects(captured.getSecret('fixture://bind-password'), {
    message: 'The original disposable provider is unavailable',
  });
  assert.equal(redirected, 0);
});

test('LDAP secret capture retains the original function and receiver without reading bind, name or length', async () => {
  let effects = 0,
    calls = 0;
  const provider = {
    async get(reference: string) {
      assert.equal(this, provider);
      calls++;
      return { bytes: Buffer.from(reference), keyVersion: 'fixture' };
    },
  };
  for (const field of ['bind', 'name', 'length'])
    Object.defineProperty(provider.get, field, {
      get() {
        effects++;
        throw new Error('Executable LDAP secret metadata');
      },
    });
  const input = { ...settings(), secretProvider: provider },
    captured = capture(input);
  assert.ok(createLdapService(input));
  assert.equal(calls, 0);
  provider.get = async () => {
    throw new Error('Late LDAP secret replacement');
  };
  assert.equal(
    (await captured.getSecret('fixture://bind-dn')).bytes.toString(),
    'fixture://bind-dn',
  );
  assert.equal(calls, 1);
  assert.equal(effects, 0);
});

test('LDAP secret proxies and hidden classification beyond the bound fail without executing traps', () => {
  const input = settings();
  let effects = 0;
  const traps = {
    get() {
      effects++;
      throw new Error('Executable LDAP provider get');
    },
    getOwnPropertyDescriptor() {
      effects++;
      throw new Error('Executable LDAP descriptor');
    },
    getPrototypeOf() {
      effects++;
      throw new Error('Executable LDAP prototype');
    },
    apply() {
      effects++;
      throw new Error('Executable LDAP provider call');
    },
  };
  for (const secretProvider of [
    new Proxy(input.secretProvider, traps),
    { get: new Proxy(input.secretProvider.get, traps) },
    Object.create(new Proxy({}, traps)) as typeof input.secretProvider,
  ])
    assert.throws(() => createLdapService({ ...input, secretProvider }), {
      code: 'EK_LDAP_FILTER',
    });
  let deep: object = { usage: 'test-only' };
  for (let depth = 0; depth < 65; depth++) deep = Object.create(deep) as object;
  const hidden = Object.create(deep) as typeof input.secretProvider;
  Object.defineProperty(hidden, 'get', { value: input.secretProvider.get });
  assert.throws(
    () => createLdapService({ ...input, environment: 'production', secretProvider: hidden }),
    { code: 'EK_LDAP_FILTER' },
  );
  assert.equal(effects, 0);
});
