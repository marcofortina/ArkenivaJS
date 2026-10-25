// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApplication, KitError } from '@arkenivajs/core';
import { mariadbPlugin } from '@arkenivajs/database-mariadb';

/** Exercise real InnoDB writes in one owned disposable table, then close every resource. */
export async function runMariadbOrdersExample() {
  if (process.env.ARKENIVA_MARIADB_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The orders example requires an explicitly disposable MariaDB database',
    });
  if (!process.env.ARKENIVA_MARIADB_URL)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'ARKENIVA_MARIADB_URL is required' });
  const app = await createApplication({
    service: { name: 'mariadb-orders-example', version: '1.0.0', environment: 'development' },
    plugins: [mariadbPlugin()],
    databases: {
      main: { driver: 'mariadb', connectionStringEnv: 'ARKENIVA_MARIADB_URL', poolMax: 2 },
    },
  });
  const table = 'orders_' + randomBytes(12).toString('hex');
  // Identifiers cannot be bound; only this bounded random hexadecimal allowlist is interpolated.
  assert.match(table, /^orders_[a-f0-9]{24}$/);
  let ready = false;
  try {
    await app.start();
    ready = true;
    // DDL runs outside the business transaction because MariaDB can implicitly commit it.
    await app.sql.execute('main', {
      text: `CREATE TABLE ${table} (id BIGINT PRIMARY KEY, total DECIMAL(12,2) NOT NULL) ENGINE=InnoDB`,
    });
    const insert = {
      text: `INSERT INTO ${table} (id,total) VALUES (:id,:total)`,
      bindings: { id: 9007199254740993n, total: '5.25' },
    };
    await app.sql.transaction('main', async (tx) => {
      const result = await tx.execute(insert);
      assert.equal(result.metadata.affectedRows, 1);
    });
    await assert.rejects(
      app.sql.execute('main', insert),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_DATABASE_CONSTRAINT' &&
        error.details?.errno === 1062,
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
        text: `SELECT id FROM ${table} WHERE id=:id`,
        bindings: { id: 2n },
      }),
      null,
    );
    const result = await app.sql.query<{ id: bigint; total: string }>('main', {
      text: `SELECT id,total FROM ${table} ORDER BY id`,
    });
    assert.deepEqual(result.rows, [{ id: 9007199254740993n, total: '5.25' }]);
    // MariaDB returns native bigint; an explicit string DTO keeps the JSON boundary exact.
    const rows = result.rows.map(({ id, total }) => ({ id: id.toString(), total }));
    return { rows, duplicateRejected: true, rollbackVerified: true };
  } finally {
    try {
      if (ready) await app.sql.execute('main', { text: `DROP TABLE IF EXISTS ${table}` });
    } finally {
      await app.stop();
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runMariadbOrdersExample()));
  } catch (error) {
    console.error(
      JSON.stringify(
        error instanceof KitError
          ? error.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The MariaDB example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
