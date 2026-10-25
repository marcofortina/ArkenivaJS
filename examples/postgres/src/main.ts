// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';

/** Exercise real SQL in an owned temporary schema, then release every resource. */
export async function runOrdersExample() {
  if (process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The orders example requires an explicitly disposable PostgreSQL database',
    });
  if (!process.env.DATABASE_URL)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'DATABASE_URL is required' });
  const app = await createApplication({
    service: { name: 'orders-example', version: '1.0.0', environment: 'development' },
    plugins: [postgresPlugin()],
    databases: {
      main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 2 },
    },
  });
  const schema = 'orders_' + randomBytes(12).toString('hex');
  // Bind parameters cannot represent identifiers; only this random allowlist is interpolated.
  assert.match(schema, /^orders_[a-f0-9]{24}$/);
  let created = false;
  try {
    await app.start();
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    created = true;
    await app.sql.execute('main', {
      text: `CREATE TABLE ${schema}.orders(id BIGINT PRIMARY KEY, tenant_id TEXT NOT NULL, total NUMERIC(12,2) NOT NULL)`,
    });
    // This fixed demo tenant is not a substitute for verified request identity in an HTTP service.
    const insert = {
      text: `INSERT INTO ${schema}.orders(id,tenant_id,total) VALUES (:id,:tenant,:total) RETURNING id,total`,
      bindings: { id: 9007199254740993n, tenant: 'demo', total: '5.25' },
    };
    await app.sql.transaction('main', async (tx) => {
      const result = await tx.execute(insert);
      assert.equal(result.metadata.affectedRows, 1);
    });
    await assert.rejects(
      app.sql.execute('main', insert),
      (error: unknown) => error instanceof KitError && error.code === 'EK_DATABASE_CONSTRAINT',
    );
    const rollback = new Error('Rollback demonstration');
    await assert.rejects(
      app.sql.transaction('main', async (tx) => {
        await tx.execute({ ...insert, bindings: { ...insert.bindings, id: 2n } });
        throw rollback;
      }),
      (error) => error === rollback,
    );
    assert.equal(
      await app.sql.queryOne('main', {
        text: `SELECT id FROM ${schema}.orders WHERE id=:id`,
        bindings: { id: 2n },
      }),
      null,
    );
    const result = await app.sql.query<{ id: string; total: string }>('main', {
      text: `SELECT id,total FROM ${schema}.orders WHERE tenant_id=:tenant`,
      bindings: { tenant: 'demo' },
    });
    assert.deepEqual(result.rows, [{ id: '9007199254740993', total: '5.25' }]);
    return { rows: result.rows, duplicateRejected: true, rollbackVerified: true };
  } finally {
    try {
      if (created) await app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
    } finally {
      await app.stop();
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runOrdersExample()));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The PostgreSQL example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
