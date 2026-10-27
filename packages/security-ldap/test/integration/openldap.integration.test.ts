// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { KitError } from '@arkenivajs/core';
import { createLdapService } from '../../dist/index.js';
import type { LdapSettings, SecretValue } from '../../dist/index.js';

const path = process.env.ARKENIVA_LDAP_FIXTURE;
if (!path) throw new Error('The owned OpenLDAP fixture metadata path is required');
const metadata = JSON.parse(await readFile(path, 'utf8')) as {
  bindDn: string;
  bindPassword: string;
  userPassword: string;
  baseDn: string;
  groupBaseDn: string;
  caPem: string;
};
const secrets = new Map<string, SecretValue>([
  ['fixture://bind-dn', { bytes: Buffer.from(metadata.bindDn), keyVersion: 'fixture-version' }],
  [
    'fixture://bind-password',
    { bytes: Buffer.from(metadata.bindPassword), keyVersion: 'fixture-version' },
  ],
  ['fixture://trust', { bytes: Buffer.from(metadata.caPem), keyVersion: 'fixture-version' }],
]);
const settings = (change: Partial<LdapSettings> = {}): LdapSettings => ({
  url: 'ldaps://127.0.0.1:16389',
  baseDn: metadata.baseDn,
  groupSearchBaseDn: metadata.groupBaseDn,
  userFilterTemplate: '(uid={username})',
  serviceBindDnRef: 'fixture://bind-dn',
  serviceBindPasswordRef: 'fixture://bind-password',
  tlsTrustBundleRef: 'fixture://trust',
  timeoutMs: 5000,
  environment: 'test',
  secretProvider: {
    async get(reference) {
      const value = secrets.get(reference);
      if (!value) throw new Error('Fixture reference unavailable');
      return value;
    },
  },
  ...change,
});
const query = {
  baseDn: metadata.baseDn,
  filter: { template: '(objectClass={kind})', values: { kind: 'inetOrgPerson' } },
  attributes: ['uid', 'cn'],
  pageSize: 2,
};
function withoutTrust(change: Partial<LdapSettings> = {}): LdapSettings {
  const { tlsTrustBundleRef, ...rest } = settings(change);
  void tlsTrustBundleRef;
  return rest;
}
test('OpenLDAP verified LDAPS finds a unique user, projects immutable attributes and verifies an isolated user bind', async () => {
  const directory = createLdapService(settings());
  assert.equal(await directory.ping(), true);
  const user = await directory.findUser({ username: 'alice' });
  assert.ok(user);
  assert.equal(user.uid, 'alice');
  assert.ok(Object.isFrozen(user.attributes.uid));
  assert.equal(
    Object.keys(user.attributes).some((name) => /password/i.test(name)),
    false,
  );
  assert.equal(
    await directory.verifyCredentials({ username: 'alice' }, metadata.userPassword),
    true,
  );
  assert.equal(
    await directory.verifyCredentials({ username: 'alice' }, randomBytes(32).toString('base64url')),
    false,
  );
  assert.equal(
    await directory.verifyCredentials({ username: 'missing' }, metadata.userPassword),
    false,
  );
  assert.equal(await directory.ping(), true);
});
test('OpenLDAP STARTTLS is verified before credentials and has no plaintext fallback', async () => {
  const directory = createLdapService(
    settings({ url: 'ldap://127.0.0.1:13389', requireStartTls: true }),
  );
  assert.equal(await directory.ping(), true);
  assert.equal(await directory.verifyCredentials({ username: 'bob' }, metadata.userPassword), true);
  const untrusted = createLdapService(
    withoutTrust({ url: 'ldap://127.0.0.1:13389', requireStartTls: true }),
  );
  await assert.rejects(
    untrusted.ping(),
    (error: unknown) => error instanceof KitError && error.code === 'EK_LDAP_CONNECT',
  );
});
test('OpenLDAP rejects wrong SAN and unknown CAs without returning authentication false', async () => {
  for (const directory of [
    createLdapService(settings({ url: 'ldaps://127.0.0.1:16390' })),
    createLdapService(withoutTrust()),
  ]) {
    await assert.rejects(
      directory.ping(),
      (error: unknown) => error instanceof KitError && error.code === 'EK_LDAP_CONNECT',
    );
    await assert.rejects(directory.verifyCredentials({ username: 'alice' }, metadata.userPassword));
  }
});
test('OpenLDAP injection and Unicode are native assertion values, and ambiguous users fail explicitly', async () => {
  const directory = createLdapService(settings());
  assert.equal(await directory.findUser({ username: '*)(|(uid=*))' }), null);
  assert.equal((await directory.findUser({ username: 'étoile' }))?.uid, 'étoile');
  await assert.rejects(
    directory.findUser({ username: 'duplicate' }),
    (error: unknown) => error instanceof KitError && error.code === 'EK_LDAP_SEARCH',
  );
  await assert.rejects(
    directory.verifyCredentials({ username: 'duplicate' }, metadata.userPassword),
  );
});
test('OpenLDAP paged iteration is complete and exceeding an entry limit never silently truncates', async () => {
  const directory = createLdapService(settings()),
    entries = [];
  for await (const entry of directory.search(query)) entries.push(entry);
  assert.equal(entries.length, 21);
  assert.equal(new Set(entries.map((entry) => entry.dn)).size, 21);
  let count = 0;
  await assert.rejects(async () => {
    for await (const entry of directory.search({ ...query, maxEntries: 3 })) {
      assert.ok(entry.dn);
      count++;
    }
  });
  assert.ok(count <= 3);
  assert.equal(await directory.ping(), true);
});
test('OpenLDAP nested group traversal detects cycles, deduplicates groups and reports depth overflow', async () => {
  const directory = createLdapService(settings()),
    user = await directory.findUser({ username: 'alice' });
  assert.ok(user);
  const groups = await directory.getGroups(user.dn);
  assert.deepEqual(groups.map((group) => group.name).sort(), ['company', 'engineering']);
  assert.ok(Object.isFrozen(groups));
  await assert.rejects(
    createLdapService(settings({ maxGroupDepth: 1 })).getGroups(user.dn),
    (error: unknown) => error instanceof KitError && error.code === 'EK_LDAP_SEARCH',
  );
  await assert.rejects(createLdapService(settings({ maxEntries: 1 })).getGroups(user.dn));
  assert.deepEqual(await directory.getGroups('cn=*)(member=*),dc=foreign,dc=invalid'), []);
});
test('OpenLDAP early iterator return, concurrent next rejection, cancellation and paused deadlines release native resources', async () => {
  const directory = createLdapService(settings()),
    first = directory.search(query)[Symbol.asyncIterator]();
  const pending = first.next();
  await assert.rejects(
    first.next(),
    (error: unknown) => error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE',
  );
  assert.equal((await pending).done, false);
  await first.return!();
  const controller = new AbortController(),
    second = directory.search(query, { signal: controller.signal })[Symbol.asyncIterator]();
  assert.equal((await second.next()).done, false);
  controller.abort();
  await assert.rejects(
    second.next(),
    (error: unknown) => error instanceof KitError && error.code === 'EK_ABORTED',
  );
  await second.return!();
  const held = directory.search(query, { timeoutMs: 700 })[Symbol.asyncIterator]();
  assert.equal((await held.next()).done, false);
  await delay(750);
  await assert.rejects(
    held.next(),
    (error: unknown) => error instanceof KitError && error.code === 'EK_TIMEOUT',
  );
  await held.return!();
  assert.equal(await directory.ping(), true);
});
test('OpenLDAP service bind failure is an operational error and external provider buffers survive operations', async () => {
  const original = secrets.get('fixture://bind-password')!.bytes.slice(),
    directory = createLdapService(
      settings({
        secretProvider: {
          async get(reference) {
            if (reference === 'fixture://bind-password')
              return {
                bytes: randomBytes(24).toString('base64url') as never,
                keyVersion: 'fixture-version',
              };
            return secrets.get(reference)!;
          },
        },
      }),
    );
  await assert.rejects(directory.verifyCredentials({ username: 'alice' }, metadata.userPassword));
  const wrongBind = createLdapService(
    settings({
      secretProvider: {
        async get(reference) {
          return reference === 'fixture://bind-password'
            ? {
                bytes: Buffer.from(randomBytes(24).toString('base64url')),
                keyVersion: 'fixture-version',
              }
            : secrets.get(reference)!;
        },
      },
    }),
  );
  await assert.rejects(
    wrongBind.verifyCredentials({ username: 'alice' }, metadata.userPassword),
    (error: unknown) => error instanceof KitError && error.code === 'EK_LDAP_BIND',
  );
  assert.deepEqual(secrets.get('fixture://bind-password')!.bytes, original);
});
test('OpenLDAP native debug and dynamic loader environment settings are excluded from child execution', async () => {
  const beforeDebug = process.env.NODE_DEBUG,
    beforeOptions = process.env.NODE_OPTIONS;
  process.env.NODE_DEBUG = 'ldapts';
  process.env.NODE_OPTIONS = '--require=/nonexistent/unsafe-directory-loader.cjs';
  try {
    assert.equal(
      await createLdapService(settings()).verifyCredentials(
        { username: 'alice' },
        metadata.userPassword,
      ),
      true,
    );
  } finally {
    if (beforeDebug === undefined) delete process.env.NODE_DEBUG;
    else process.env.NODE_DEBUG = beforeDebug;
    if (beforeOptions === undefined) delete process.env.NODE_OPTIONS;
    else process.env.NODE_OPTIONS = beforeOptions;
  }
});
test('OpenLDAP referrals fail explicitly and never open the advertised foreign connection', async () => {
  let connections = 0;
  const trap = createServer((socket) => {
    connections++;
    socket.destroy();
  });
  await new Promise<void>((resolve) => trap.listen(19389, '127.0.0.1', resolve));
  try {
    const baseDn = metadata.groupBaseDn.replace('ou=groups,', 'ou=referrals,'),
      directory = createLdapService(settings({ baseDn }));
    await assert.rejects(
      async () => {
        for await (const entry of directory.search({
          baseDn,
          filter: { template: '(objectClass=*)', values: {} },
          attributes: ['cn'],
        }))
          assert.ok(entry.dn);
      },
      (error: unknown) => error instanceof KitError && error.code === 'EK_LDAP_SEARCH',
    );
    assert.equal(connections, 0);
  } finally {
    await new Promise<void>((resolve) => trap.close(() => resolve()));
  }
});
