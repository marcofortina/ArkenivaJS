// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import oracledb from 'oracledb';
import type { Pool, Lob } from 'oracledb';
import { createApplication, KitError } from '@arkenivajs/core';
import { oraclePlugin } from '@arkenivajs/database-oracle';

test(
  'EK-DB-001 opt-in disposable Oracle SQL, exact values, native LOB, OUT binds and transactions',
  { timeout: 120_000 },
  async () => {
    assert.equal(
      process.env.ARKENIVA_ORACLE_DISPOSABLE,
      '1',
      'Explicitly authorize only a disposable Oracle schema',
    );
    assert.ok(
      process.env.ARKENIVA_ORACLE_URL,
      'ARKENIVA_ORACLE_URL is required for optional live validation',
    );
    const mode = process.env.ARKENIVA_ORACLE_MODE ?? 'thin';
    assert.ok(mode === 'thin' || mode === 'thick', 'ARKENIVA_ORACLE_MODE must be thin or thick');
    const app = await createApplication({
      service: { name: 'oracle-live-test', version: '1.0.0', environment: 'test' },
      plugins: [oraclePlugin({ mode })],
      databases: {
        main: { driver: 'oracle', connectionStringEnv: 'ARKENIVA_ORACLE_URL', poolMax: 2 },
      },
    });
    const table = 'ARKENIVA_' + randomBytes(8).toString('hex').toUpperCase();
    assert.match(table, /^ARKENIVA_[A-F0-9]{16}$/);
    let created = false;
    try {
      await app.start();
      const exact = await app.sql.queryOne('main', {
        text: `SELECT CAST(:large AS NUMBER(38,0)) AS "large", CAST(:decimal AS NUMBER(30,8)) AS "decimal", UTL_RAW.CAST_TO_RAW(:bytes) AS "bytes", TO_CHAR(TO_TIMESTAMP(:stamp,'YYYY-MM-DD HH24:MI:SS.FF9'),'YYYY-MM-DD HH24:MI:SS.FF9') AS "stamp" FROM DUAL`,
        bindings: {
          large: 900719925474099312345n,
          decimal: '1234567890123456.12345678',
          bytes: 'binary',
          stamp: '2026-10-25 01:30:00.123456789',
        },
      });
      assert.equal(exact?.large, '900719925474099312345');
      assert.equal(exact?.decimal, '1234567890123456.12345678');
      assert.deepEqual(exact?.bytes, Buffer.from('binary'));
      assert.equal(exact?.stamp, '2026-10-25 01:30:00.123456789');
      const hostile = "' OR 1=1 --";
      assert.equal(
        (
          await app.sql.queryOne('main', {
            text: 'SELECT :value AS "value" FROM DUAL',
            bindings: { value: hostile },
          })
        )?.value,
        hostile,
      );
      await assert.rejects(
        app.sql.queryOne('main', { text: 'SELECT LEVEL AS "id" FROM DUAL CONNECT BY LEVEL <= 3' }),
        (e) => e instanceof KitError && e.code === 'EK_DATABASE_QUERY',
      );
      await assert.rejects(
        app.sql.query(
          'main',
          { text: 'SELECT LEVEL AS "id" FROM DUAL CONNECT BY LEVEL <= 4' },
          { maxRows: 3 },
        ),
        (e) => e instanceof KitError && e.details?.limitExceeded === true,
      );
      await app.sql.execute('main', {
        text: `CREATE TABLE ${table} (id NUMBER(38,0) PRIMARY KEY, body CLOB)`,
      });
      created = true;
      await app.sql.transaction('main', async (tx) => {
        await tx.execute({
          text: `INSERT INTO ${table} (id) VALUES (:id)`,
          bindings: { id: 9007199254740993n },
        });
      });
      const rollback = new Error('Rollback demonstration');
      await assert.rejects(
        app.sql.transaction('main', async (tx) => {
          await tx.execute({ text: `INSERT INTO ${table} (id) VALUES (:id)`, bindings: { id: 2 } });
          throw rollback;
        }),
        (e) => e === rollback,
      );
      assert.equal(
        await app.sql.queryOne('main', {
          text: `SELECT id FROM ${table} WHERE id = :id`,
          bindings: { id: 2 },
        }),
        null,
      );
      await assert.rejects(
        app.sql.execute('main', {
          text: `INSERT INTO ${table} (id) VALUES (:id)`,
          bindings: { id: 9007199254740993n },
        }),
        (e) => e instanceof KitError && e.code === 'EK_DATABASE_CONSTRAINT',
      );
      const pool = app.sql.native('main') as Pool,
        client = await pool.getConnection();
      let failed = true;
      try {
        client.callTimeout = 5000;
        const inserted = await client.execute(
          `INSERT INTO ${table} (id,body) VALUES (3,EMPTY_CLOB()) RETURNING body INTO :body`,
          { body: { dir: oracledb.BIND_OUT, type: oracledb.DB_TYPE_CLOB } },
          { autoCommit: false },
        );
        const writable = (inserted.outBinds as { body: Lob[] }).body[0]!;
        const body = 'Exact streamed Oracle CLOB';
        await new Promise<void>((resolve, reject) => {
          writable.once('finish', resolve);
          writable.once('error', reject);
          writable.end(body);
        });
        await client.commit();
        const selected = await client.execute<{ body: Lob }>(
          `SELECT body AS "body" FROM ${table} WHERE id=3`,
          {},
          {
            resultSet: true,
            prefetchRows: 0,
            fetchArraySize: 1,
            outFormat: oracledb.OUT_FORMAT_OBJECT,
            fetchTypeHandler: (metadata) => ({ type: metadata.dbType! }),
          },
        );
        try {
          const row = (await selected.resultSet!.getRows(1))[0]!;
          let received = '';
          await pipeline(
            row.body,
            new Writable({
              write(chunk, _encoding, done) {
                received += String(chunk);
                done(received.length > 1024 ? new Error('LOB output limit exceeded') : undefined);
              },
            }),
            { signal: AbortSignal.timeout(5000) },
          );
          assert.equal(received, body);
        } finally {
          await selected.resultSet!.close();
        }
        const inout = await client.execute('BEGIN :value := :value + 1; END;', {
          value: { dir: oracledb.BIND_INOUT, type: oracledb.DB_TYPE_NUMBER, val: 7 },
        });
        assert.equal((inout.outBinds as { value: number }).value, 8);
        console.log(
          JSON.stringify({
            driver: oracledb.versionString,
            server: client.oracleServerVersionString,
            mode: client.thin ? 'thin' : 'thick',
            node: process.version,
            platform: process.platform,
            architecture: process.arch,
            testedAt: new Date().toISOString(),
          }),
        );
        failed = false;
      } finally {
        await client.close({ drop: failed });
      }
    } finally {
      try {
        if (created) await app.sql.execute('main', { text: `DROP TABLE ${table} PURGE` });
      } finally {
        await app.stop();
      }
    }
  },
);
