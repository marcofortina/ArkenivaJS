// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { OracleConnection } from '../../dist/connection.js';
import { oracleConfiguration } from '../../dist/config.js';

test('EK-DB-001 actual Thin SDK pools construct and close offline without Oracle Client or database connections', async () => {
  const variable = 'ARKENIVA_ORACLE_OFFLINE_POOL_TEST';
  process.env[variable] = 'oracle://offline:offline@127.0.0.1:1/UNREACHABLE';
  const connections: OracleConnection[] = [];
  try {
    for (const name of ['first', 'second']) {
      const configuration = oracleConfiguration(
        { driver: 'oracle', connectionStringEnv: variable, poolMin: 0, poolMax: 1 },
        'test',
      );
      const connection = await OracleConnection.create(name, configuration, {}, 'thin');
      connections.push(connection);
      assert.equal(connection.native().constructor.name, 'Pool');
      assert.equal(connection.stats().total, 0);
      assert.equal(connection.stats().nativeActive, 0);
    }
    assert.notEqual(connections[0]!.native(), connections[1]!.native());
  } finally {
    delete process.env[variable];
    await Promise.all(connections.map((connection) => connection.close()));
  }
});
