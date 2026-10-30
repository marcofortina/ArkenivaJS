// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createPool } from 'mysql2';

const text =
  'SELECT :marker AS text_value, :marker AS repeated, CAST(:exact AS SIGNED) AS exact_value';
export const mysqlQueryInput = (fixture) =>
  Object.freeze({
    text,
    bindings: Object.freeze({ marker: fixture.marker, exact: BigInt(fixture.exact) }),
  });
const expected = (fixture) => ({
  text_value: fixture.marker,
  repeated: fixture.marker,
  exact_value: fixture.exact,
});

export function mysqlQueryConnection(fixture) {
  try {
    const url = new URL(fixture.url);
    assert.equal(url.protocol, 'mysql:');
    assert.equal(url.hostname, 'localhost');
    assert.ok(url.port && url.username && url.password && url.pathname.length > 1);
    assert.equal(url.searchParams.get('ssl'), 'verify-full');
    assert.ok(url.searchParams.get('sslca')?.startsWith('/'));
    for (const key of url.searchParams.keys()) {
      assert.ok(['ssl', 'sslca'].includes(key));
      assert.equal(url.searchParams.getAll(key).length, 1);
    }
    assert.equal(url.hash, '');
    return url;
  } catch {
    throw new Error(
      'The owned MySQL comparison requires an authenticated verified-TLS localhost fixture',
    );
  }
}

/** Fixed positional prepared input corresponds only to the declared valid named-bind corpus. */
export async function nativeMysqlQuery(fixture) {
  const url = mysqlQueryConnection(fixture);
  const pool = createPool({
    host: url.hostname,
    port: Number(url.port),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: decodeURIComponent(url.pathname.slice(1)),
    ssl: {
      ca: await readFile(url.searchParams.get('sslca')),
      rejectUnauthorized: true,
      verifyIdentity: true,
      minVersion: 'TLSv1.2',
    },
    charset: 'UTF8MB4_UNICODE_CI',
    timezone: 'Z',
    supportBigNumbers: true,
    bigNumberStrings: true,
    decimalNumbers: false,
    dateStrings: true,
    jsonStrings: true,
    rowsAsArray: false,
    namedPlaceholders: false,
    multipleStatements: false,
    flags: ['-LOCAL_FILES'],
    connectTimeout: 5000,
    waitForConnections: true,
    connectionLimit: 2,
    maxIdle: 2,
    queueLimit: 128,
    maxPreparedStatements: 100,
    resetOnRelease: false,
    enableKeepAlive: true,
    disableEval: true,
  });
  pool.on('error', () => undefined);
  const promisePool = pool.promise();
  try {
    await promisePool.query('SELECT 1');
  } catch {
    await promisePool.end();
    throw new Error('The owned native MySQL connection failed');
  }
  let active = 0,
    pending = 0;
  return {
    native: () => pool,
    stats: () => ({ active, pendingAcquires: pending, observerFailures: 0, cleanupFailures: 0 }),
    async queryOne(name, query) {
      assert.equal(name, 'main');
      assert.equal(query.text, text);
      pending++;
      let client;
      try {
        client = await new Promise((done, reject) =>
          pool.getConnection((cause, value) => (cause ? reject(cause) : done(value))),
        );
        pending--;
        active++;
        await new Promise((done, reject) =>
          client.reset((cause) => (cause ? reject(cause) : done())),
        );
        await client.promise().query('SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci');
        await client
          .promise()
          .query(
            "SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION', time_zone = '+00:00', autocommit = 1",
          );
        const [state] = await client
          .promise()
          .query(
            'SELECT @@session.sql_mode AS mode, @@session.character_set_client AS encoding, @@session.time_zone AS zone',
          );
        assert.equal(state[0].encoding, 'utf8mb4');
        assert.equal(state[0].zone, '+00:00');
        const command = client.execute(
          'SELECT ? AS text_value, ? AS repeated, CAST(? AS SIGNED) AS exact_value',
          [query.bindings.marker, query.bindings.marker, String(query.bindings.exact)],
        );
        command.on('error', () => undefined);
        const rows = [];
        for await (const row of command.stream({ highWaterMark: 1 })) {
          assert.ok(rows.length < 2);
          rows.push({ ...row });
        }
        assert.equal(rows.length, 1);
        return rows[0];
      } finally {
        if (client) {
          active--;
          client.release();
        } else pending--;
      }
    },
    close: () => promisePool.end(),
  };
}

export async function verifyMysqlQuery(service, fixture) {
  const [version] = await service.native('main').promise().query('SELECT VERSION() AS version');
  assert.match(version[0].version, /^9\.7\.4/);
  assert.deepEqual(await service.queryOne('main', mysqlQueryInput(fixture)), expected(fixture));
  return {
    serverVersion: version[0].version,
    actualPreparedRowVerified: true,
    repeatedBindVerified: true,
    exactBigintTextVerified: true,
  };
}

export function mysqlQueryWorkload(service, fixture) {
  const query = mysqlQueryInput(fixture),
    row = expected(fixture);
  return {
    queryOne: async () => {
      const result = await service.queryOne('main', query);
      assert.deepEqual(result, row);
      return result;
    },
  };
}

export function completeMysqlQuery(service) {
  const stats = service.stats('main');
  for (const key of ['active', 'pendingAcquires', 'observerFailures', 'cleanupFailures'])
    assert.equal(stats[key], 0);
  return {
    trackedCheckoutsDrained: true,
    pendingAcquisitionsDrained: true,
    nativePoolCountersAvailable: false,
  };
}
