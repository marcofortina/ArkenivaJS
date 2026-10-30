// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { checkServerIdentity } from 'node:tls';
import { createPool } from 'mariadb';

const text =
  'SELECT :marker AS text_value, :marker AS repeated, CAST(:exact AS SIGNED) AS exact_value';
export const mariadbQueryInput = (fixture) =>
  Object.freeze({
    text,
    bindings: Object.freeze({ marker: fixture.marker, exact: BigInt(fixture.exact) }),
  });
const expected = (fixture) => ({
  text_value: fixture.marker,
  repeated: fixture.marker,
  exact_value: BigInt(fixture.exact),
});

export function mariadbQueryConnection(fixture) {
  try {
    const url = new URL(fixture.url);
    assert.equal(url.protocol, 'mariadb:');
    assert.ok(['localhost', '127.0.0.1'].includes(url.hostname));
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
      'The owned MariaDB comparison requires an authenticated verified-TLS loopback fixture',
    );
  }
}

/** The native MariaDB prepared stream retains bigint values without MySQL-specific normalization. */
export async function nativeMariadbQuery(fixture) {
  const url = mariadbQueryConnection(fixture),
    host = url.hostname;
  const pool = createPool({
    host,
    port: Number(url.port),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    database: decodeURIComponent(url.pathname.slice(1)),
    ssl: {
      ca: await readFile(url.searchParams.get('sslca')),
      host,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      ...(host === 'localhost' ? { servername: host } : {}),
      checkServerIdentity: (_name, certificate) => checkServerIdentity(host, certificate),
    },
    charset: 'utf8mb4',
    collation: 'UTF8MB4_UNICODE_CI',
    timezone: '+00:00',
    bigIntAsNumber: false,
    insertIdAsNumber: false,
    decimalAsNumber: false,
    checkNumberRange: true,
    dateStrings: true,
    autoJsonMap: false,
    rowsAsArray: false,
    metaAsArray: false,
    namedPlaceholders: false,
    multipleStatements: false,
    permitLocalInfile: false,
    connectTimeout: 5000,
    acquireTimeout: 5000,
    initializationTimeout: 5000,
    connectionLimit: 2,
    minimumIdle: 0,
    idleTimeout: 10,
    minDelayValidation: 0,
    prepareCacheLength: 100,
    resetAfterUse: false,
    noControlAfterUse: false,
    trace: false,
    logParam: false,
    logger: {},
  });
  pool.on('error', () => undefined);
  try {
    const client = await pool.getConnection();
    try {
      await client.ping();
    } finally {
      await client.release();
    }
  } catch {
    await pool.end();
    throw new Error('The owned native MariaDB connection failed');
  }
  return {
    native: () => pool,
    async queryOne(name, query) {
      assert.equal(name, 'main');
      assert.equal(query.text, text);
      const client = await pool.getConnection();
      let prepared;
      try {
        await client.reset();
        await client.query('SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci');
        await client.query(
          "SET SESSION sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION', time_zone = '+00:00', autocommit = 1",
        );
        const state = await client.query(
          'SELECT @@session.sql_mode AS mode, @@session.character_set_client AS encoding, @@session.time_zone AS zone',
        );
        assert.equal(state[0].encoding, 'utf8mb4');
        assert.equal(state[0].zone, '+00:00');
        prepared = await client.prepare(
          'SELECT ? AS text_value, ? AS repeated, CAST(? AS SIGNED) AS exact_value',
        );
        const rows = [];
        for await (const row of prepared.executeStream([
          query.bindings.marker,
          query.bindings.marker,
          String(query.bindings.exact),
        ])) {
          assert.ok(rows.length < 2);
          rows.push({ ...row });
        }
        assert.equal(rows.length, 1);
        return rows[0];
      } finally {
        try {
          prepared?.close();
        } finally {
          await client.release();
        }
      }
    },
    close: () => pool.end(),
  };
}

export async function verifyMariadbQuery(service, fixture) {
  const version = await service.native('main').query('SELECT VERSION() AS version');
  assert.match(version[0].version, /^12\.3\.3-MariaDB/);
  assert.deepEqual(await service.queryOne('main', mariadbQueryInput(fixture)), expected(fixture));
  return {
    serverVersion: version[0].version,
    actualPreparedRowVerified: true,
    repeatedBindVerified: true,
    exactNativeBigintVerified: true,
  };
}

export function mariadbQueryWorkload(service, fixture) {
  const query = mariadbQueryInput(fixture),
    row = expected(fixture);
  return {
    queryOne: async () => {
      const result = await service.queryOne('main', query);
      assert.deepEqual(result, row);
      return result;
    },
  };
}

export function completeMariadbQuery(service) {
  const pool = service.native('main');
  assert.equal(pool.activeConnections(), 0);
  assert.equal(pool.taskQueueSize(), 0);
  assert.equal(pool.idleConnections(), pool.totalConnections());
  assert.ok(pool.totalConnections() >= 1 && pool.totalConnections() <= 2);
  return {
    nativePoolDrained: true,
    poolConnections: pool.totalConnections(),
    exactNativeBigintPreserved: true,
  };
}
