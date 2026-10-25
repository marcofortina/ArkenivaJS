// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { DatabaseDefinition } from '@arkenivajs/core';
import { oracleConfiguration } from '../../dist/config.js';
const variable = 'ARKENIVA_ORACLE_CONFIGURATION_TEST';
const definition: DatabaseDefinition = { driver: 'oracle', connectionStringEnv: variable };
test('EK-CONF-001 Oracle captures explicit credentials, transport policy and bounded native pool options', () => {
  process.env[variable] = 'oracle://app:p%40ss@localhost/FREEPDB1';
  try {
    const local = oracleConfiguration(definition, 'test');
    assert.equal(local.connectString, 'tcp://localhost:1521/FREEPDB1');
    assert.equal(local.password, 'p@ss');
    assert.equal(local.poolMin, 0);
    assert.equal(local.poolMax, 10);
    assert.equal(local.queueTimeout, 5000);
    assert.equal(local.retryCount, 0);
    assert.equal(local.externalAuth, false);
    assert.equal(local.sslServerDNMatch, true);
    assert.equal(local.sslAllowWeakDNMatch, false);
    assert.notEqual(local.poolAlias, oracleConfiguration(definition, 'test').poolAlias);
    assert.equal(
      oracleConfiguration(definition, 'production').connectString,
      'tcps://localhost:2484/FREEPDB1',
    );
    process.env[variable] =
      'oracle://app:pw@[::1]:1522/FREEPDB1?ssl=verify-full&wallet=%2Fprivate%2Fwallet';
    assert.equal(
      oracleConfiguration({ ...definition, poolMin: 1, poolMax: 2 }, 'test').walletLocation,
      '/private/wallet',
    );
  } finally {
    delete process.env[variable];
  }
});
test('EK-CONF-001 Oracle rejects missing, ambiguous, ambient and insecure configuration before acquisition', () => {
  for (const bad of [undefined, '', 'bad-name', 'UPPER\n'])
    assert.throws(
      () =>
        oracleConfiguration(
          { driver: 'oracle', ...(bad === undefined ? {} : { connectionStringEnv: bad }) },
          'test',
        ),
      (e) => e instanceof KitError && e.code === 'EK_CONFIG_MISSING',
    );
  delete process.env[variable];
  assert.throws(() => oracleConfiguration(definition, 'test'));
  try {
    for (const value of [
      'oracle://app@localhost/FREE',
      'oracle://:pw@localhost/FREE',
      'postgres://app:pw@localhost/FREE',
      'oracle://app:pw@localhost/',
      'oracle://app:pw@localhost/FREE/other',
      'oracle://app:pw@remote/FREE?ssl=disable',
      'oracle://app:pw@localhost/FREE?ssl=no',
      'oracle://app:pw@localhost/FREE?unknown=yes',
      'oracle://app:pw@localhost/FREE?ssl=disable&ssl=disable',
      'oracle://app:pw@localhost/FREE?wallet=/private',
      'oracle://app:pw@localhost/FREE?ssl=verify-full&wallet=relative',
      'oracle://app:pw@localhost/FREE#fragment',
      'oracle://app:pw@localhost/FREE\n',
      'oracle://app:p%00@localhost/FREE',
      'oracle://app:%ZZ@localhost/FREE',
      'oracle://app:pw@localhost/FREE%0A',
      'oracle://app:pw@host,other/FREE',
      'oracle://app:pw@host..other/FREE',
      'oracle://app:pw@localhost:0/FREE',
    ]) {
      process.env[variable] = value;
      assert.throws(
        () => oracleConfiguration(definition, 'test'),
        (e) => e instanceof KitError && e.code === 'EK_CONFIG_INVALID',
      );
    }
    process.env[variable] = 'oracle://app:pw@127.0.0.1/FREE';
    for (const change of [
      { driver: 'mysql' },
      { endpoints: ['localhost'] },
      { poolMin: -1 },
      { poolMax: 0 },
      { poolMin: 2, poolMax: 1 },
      { poolMin: 0.1 },
      { poolMax: Number.MAX_VALUE },
    ])
      assert.throws(() =>
        oracleConfiguration({ ...definition, ...change } as DatabaseDefinition, 'test'),
      );
    assert.equal(
      oracleConfiguration(definition, 'test').connectString,
      'tcp://127.0.0.1:1521/FREE',
    );
  } finally {
    delete process.env[variable];
  }
});
