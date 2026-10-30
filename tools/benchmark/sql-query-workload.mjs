// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { checkServerIdentity } from 'node:tls';
import { Pool } from 'pg';
import Cursor from 'pg-cursor';
import { parse, toClientConfig } from 'pg-connection-string';

const smallText =
  'SELECT :value::integer AS value, :marker::text AS text_value, :value::integer AS repeated';
const exactText = 'SELECT :exact::bigint AS exact_value';
export const sqlQueryInput = (fixture) =>
  Object.freeze({ text: smallText, bindings: Object.freeze({ value: 7, marker: fixture.marker }) });
const expected = (fixture) => ({ value: 7, text_value: fixture.marker, repeated: 7 });

export function sqlQueryConnection(fixture) {
  try {
    const url = new URL(fixture.url);
    assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
    assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
    assert.ok(url.port && url.username && url.password && url.pathname.length > 1);
    assert.equal(url.searchParams.get('sslmode'), 'verify-full');
    assert.ok(url.searchParams.get('sslrootcert')?.startsWith('/'));
    const configuration = toClientConfig(parse(fixture.url));
    assert.ok(configuration.ssl && typeof configuration.ssl === 'object');
    return { configuration, url };
  } catch {
    throw new Error('The owned SQL comparison requires a verified loopback PostgreSQL fixture');
  }
}

/** Fixed positional native statements correspond only to this declared valid named-bind corpus. */
export async function nativeSqlQuery(fixture) {
  const { configuration } = sqlQueryConnection(fixture),
    host = configuration.host;
  const pool = new Pool({
    ...configuration,
    ssl: {
      ...configuration.ssl,
      rejectUnauthorized: true,
      checkServerIdentity: (_name, certificate) => checkServerIdentity(host, certificate),
    },
    max: 2,
    connectionTimeoutMillis: 5000,
    client_encoding: 'UTF8',
    query_timeout: 0,
    pipeline: false,
    enableChannelBinding: true,
  });
  pool.on('error', () => undefined);
  try {
    await pool.query('SELECT 1');
  } catch {
    await pool.end();
    throw new Error('The owned native SQL comparison connection failed');
  }
  return {
    native: () => pool,
    async queryOne(name, query) {
      assert.equal(name, 'main');
      let text, parameters;
      if (query.text === smallText) {
        text = 'SELECT $1::integer AS value, $2::text AS text_value, $1::integer AS repeated';
        parameters = [query.bindings.value, query.bindings.marker];
      } else {
        assert.equal(query.text, exactText);
        text = 'SELECT $1::bigint AS exact_value';
        parameters = [query.bindings.exact];
      }
      const client = await pool.connect();
      try {
        await client.query('DISCARD ALL');
        await client.query("SET client_encoding TO 'UTF8'; SET standard_conforming_strings TO on");
        const cursor = client.query(new Cursor(text, parameters));
        try {
          const rows = await cursor.read(2);
          assert.equal(rows.length, 1);
          return rows[0];
        } finally {
          await cursor.close();
        }
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}

export async function verifySqlQuery(service, fixture) {
  const version = await service.native('main').query('SHOW server_version_num');
  const serverMajor = Math.floor(Number(version.rows[0].server_version_num) / 10000);
  assert.ok([17, 18].includes(serverMajor));
  assert.deepEqual(await service.queryOne('main', sqlQueryInput(fixture)), expected(fixture));
  const exact = await service.queryOne('main', {
    text: exactText,
    bindings: { exact: BigInt(fixture.exact) },
  });
  assert.deepEqual(exact, { exact_value: fixture.exact });
  return {
    serverMajor,
    actualBoundRowVerified: true,
    repeatedBindVerified: true,
    exactBigintTextVerified: true,
  };
}

export function sqlQueryWorkload(service, fixture) {
  const input = sqlQueryInput(fixture),
    row = expected(fixture);
  return {
    queryOne: async () => {
      const result = await service.queryOne('main', input);
      assert.deepEqual(result, row);
      return result;
    },
  };
}

export function completeSqlQuery(service) {
  const pool = service.native('main');
  assert.equal(pool.waitingCount, 0);
  assert.equal(pool.idleCount, pool.totalCount);
  assert.ok(pool.totalCount >= 1 && pool.totalCount <= 2);
  return { nativePoolDrained: true, poolConnections: pool.totalCount };
}
