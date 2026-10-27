// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runLdapExample } from '../../dist/main.js';

if (!process.env.ARKENIVA_LDAP_FIXTURE)
  throw new Error('The owned OpenLDAP fixture metadata path is required');
test('The packed public LDAP consumer verifies OpenLDAP and exports actual private SDK metrics', async () => {
  const metadata = JSON.parse(await readFile(process.env.ARKENIVA_LDAP_FIXTURE!, 'utf8')) as {
    bindDn: string;
    bindPassword: string;
    userPassword: string;
    baseDn: string;
    groupBaseDn: string;
    caPem: string;
  };
  const values = new Map([
    ['fixture://dn', metadata.bindDn],
    ['fixture://password', metadata.bindPassword],
    ['fixture://ca', metadata.caPem],
  ]);
  const result = await runLdapExample(
    {
      url: 'ldaps://127.0.0.1:16389',
      baseDn: metadata.baseDn,
      groupSearchBaseDn: metadata.groupBaseDn,
      userFilterTemplate: '(uid={username})',
      serviceBindDnRef: 'fixture://dn',
      serviceBindPasswordRef: 'fixture://password',
      tlsTrustBundleRef: 'fixture://ca',
      environment: 'test',
      secretProvider: {
        async get(reference) {
          const value = values.get(reference);
          if (!value) throw new Error('Fixture reference unavailable');
          return { bytes: Buffer.from(value), keyVersion: 'fixture-version' };
        },
      },
    },
    'alice',
    metadata.userPassword,
  );
  assert.equal(result.found, true);
  assert.equal(result.authenticated, true);
  assert.deepEqual([...(result.groups ?? [])].sort(), ['company', 'engineering']);
  for (const name of [
    'ldap.bind.duration.ms',
    'ldap.search.count',
    'ldap.group.depth',
    'ldap.operation.duration.ms',
  ])
    assert.ok(result.metricNames.includes(name));
});
