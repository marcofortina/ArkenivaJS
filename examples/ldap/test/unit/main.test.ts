// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { KitError } from '@arkenivajs/core';
import { runLdapExample } from '../../dist/main.js';

test('The LDAP consumer denies a failed external provider without authenticating or exposing its diagnostic', async () => {
  const password = randomBytes(32).toString('base64url');
  await assert.rejects(
    runLdapExample(
      {
        url: 'ldaps://127.0.0.1:9',
        baseDn: 'ou=people,dc=fixture,dc=invalid',
        groupSearchBaseDn: 'ou=groups,dc=fixture,dc=invalid',
        userFilterTemplate: '(uid={username})',
        serviceBindDnRef: 'fixture://dn',
        serviceBindPasswordRef: 'fixture://password',
        environment: 'test',
        secretProvider: {
          async get() {
            throw new Error(password);
          },
        },
      },
      'alice',
      password,
    ),
    (error: unknown) =>
      error instanceof KitError &&
      error.code === 'EK_LDAP_BIND' &&
      !JSON.stringify(error).includes(password),
  );
});
