import test from 'node:test';
import assert from 'node:assert/strict';
import oracledb from 'oracledb';
import { KitError } from '@arkenivajs/core';
import { OracleConnection } from '../../dist/connection.js';

test('EK-DB-001 mocked Thick initialization failure, success and process-wide mode reuse do not require Oracle Client', async (context) => {
  let thin = true,
    fail = true,
    initialized = 0,
    closed = 0;
  context.mock.getter(oracledb, 'thin', () => thin);
  context.mock.method(oracledb, 'initOracleClient', () => {
    initialized++;
    if (fail) throw new Error('Oracle Client is intentionally unavailable');
    thin = false;
  });
  context.mock.method(oracledb, 'createPool', async () => ({
    poolMax: 1,
    async close() {
      closed++;
    },
  }));
  await assert.rejects(
    OracleConnection.create('test', {}, {}, 'thick'),
    (error) => error instanceof KitError && error.code === 'EK_DATABASE_CONNECT',
  );
  assert.equal(initialized, 1);
  fail = false;
  const first = await OracleConnection.create('first', {}, {}, 'thick');
  const second = await OracleConnection.create('second', {}, {}, 'thick');
  await first.close();
  await second.close();
  assert.equal(initialized, 2);
  assert.equal(closed, 2);
  await assert.rejects(
    OracleConnection.create('conflicting', {}, {}, 'thin'),
    (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
  );
});
