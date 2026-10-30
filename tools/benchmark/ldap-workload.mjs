// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { checkServerIdentity } from 'node:tls';
import { Client, EqualityFilter, InvalidCredentialsError } from 'ldapts';

export function ldapSettings(fixture) {
  const url = new URL(fixture.url);
  assert.equal(url.protocol, 'ldaps:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.href, fixture.url);
  assert.equal(url.username + url.password + url.search + url.hash, '');
  assert.ok(url.port);
  assert.equal(url.pathname, '');
  const values = new Map([
    ['bind-dn', fixture.bindDn],
    ['bind-password', fixture.bindPassword],
    ['trust', fixture.caPem],
  ]);
  return {
    url: fixture.url,
    baseDn: fixture.baseDn,
    groupSearchBaseDn: fixture.groupBaseDn,
    userFilterTemplate: '(uid={username})',
    serviceBindDnRef: 'bind-dn',
    serviceBindPasswordRef: 'bind-password',
    tlsTrustBundleRef: 'trust',
    environment: 'test',
    allowedAttributes: ['uid', 'cn'],
    timeoutMs: 5000,
    secretProvider: {
      usage: 'test-only',
      async get(reference) {
        assert.ok(values.has(reference));
        return { bytes: Buffer.from(values.get(reference)), keyVersion: 'one' };
      },
    },
  };
}

/** Every native operation uses fresh verified TLS clients and closes them after acknowledged work. */
export function nativeLdap(fixture) {
  ldapSettings(fixture);
  const connect = async (dn, password, work) => {
    const client = new Client({
      url: fixture.url,
      timeout: 5000,
      connectTimeout: 5000,
      tlsOptions: {
        ca: fixture.caPem,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        checkServerIdentity: (_name, certificate) => checkServerIdentity('127.0.0.1', certificate),
      },
    });
    try {
      await client.bind(dn, password);
      return await work(client);
    } finally {
      await client.unbind();
    }
  };
  const service = (work) => connect(fixture.bindDn, fixture.bindPassword, work);
  const find = async (client, username) => {
    const result = await client.search(fixture.baseDn, {
      scope: 'sub',
      filter: new EqualityFilter({ attribute: 'uid', value: username }),
      attributes: ['uid', 'cn'],
      sizeLimit: 2,
      paged: { pageSize: 2 },
    });
    assert.ok(result.searchEntries.length <= 1);
    if (!result.searchEntries.length) return null;
    const entry = result.searchEntries[0],
      attributes = Object.create(null);
    for (const name of ['uid', 'cn']) {
      const value = entry[name];
      const values = Array.isArray(value) ? value : [value];
      assert.ok(values.every((item) => typeof item === 'string'));
      attributes[name] = values;
    }
    return { dn: entry.dn, uid: attributes.uid[0], attributes };
  };
  return {
    ping: () => service(async () => true),
    findUser: ({ username }) => service((client) => find(client, username)),
    verifyCredentials: ({ username }, password) =>
      service(async (client) => {
        const user = await find(client, username);
        if (!user) return false;
        try {
          return await connect(user.dn, password, async () => true);
        } catch (error) {
          if (error instanceof InvalidCredentialsError) return false;
          throw error;
        }
      }),
  };
}

export async function verifyLdap(service, fixture) {
  assert.equal(await service.ping(), true);
  const found = await service.findUser({ username: 'alice' });
  assert.ok(found);
  assert.equal(found.uid, 'alice');
  const expected = await nativeLdap(fixture).findUser({ username: 'alice' });
  assert.deepEqual(JSON.parse(JSON.stringify(found)), JSON.parse(JSON.stringify(expected)));
  assert.deepEqual([...found.attributes.uid], ['alice']);
  assert.ok(found.attributes.cn.length > 0);
  assert.equal(await service.findUser({ username: 'owned-absent-comparison-user' }), null);
  assert.equal(await service.findUser({ username: '*)(uid=*)' }), null);
  assert.equal(await service.verifyCredentials({ username: 'alice' }, fixture.userPassword), true);
  assert.equal(
    await service.verifyCredentials({ username: 'alice' }, fixture.userPassword + '-incorrect'),
    false,
  );
  return {
    verifiedServiceBind: true,
    actualUserFound: true,
    absentUser: true,
    filterInjectionAbsent: true,
    correctPassword: true,
    incorrectPasswordRejected: true,
  };
}
