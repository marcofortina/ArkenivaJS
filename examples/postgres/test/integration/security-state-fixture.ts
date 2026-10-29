// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import {
  createPostgresSecurityStateStore,
  createPostgresSecurityStateTables,
} from '../../dist/security-state-store.js';

/** A separate application owns a distinct native pool while borrowing only the already-created schema. */
export async function independentSecurityStatePeer(schema: string) {
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
  assert.match(schema, /^security_[a-f0-9]{24}$/u);
  const app = await createApplication({
    service: { name: 'security-state-peer', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 4 } },
  });
  try {
    await app.start();
    return {
      app,
      store: createPostgresSecurityStateStore(app.sql, 'main', schema),
      close: () => app.stop(),
    };
  } catch (error) {
    await app.stop();
    throw error;
  }
}

/** All tables live in a fresh owned schema on the explicit disposable verified-TLS fixture. */
export async function securityStateFixture() {
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  assert.ok(process.env.DATABASE_URL, 'DATABASE_URL is required');
  const schema = 'security_' + randomBytes(12).toString('hex');
  const app = await createApplication({
    service: { name: 'security-state-fixture', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: { main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 4 } },
  });
  let created = false,
    closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    try {
      if (created) await app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
    } finally {
      await app.stop();
    }
  };
  try {
    await app.start();
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
    created = true;
    await createPostgresSecurityStateTables(app.sql, 'main', schema);
    return {
      app,
      schema,
      store: createPostgresSecurityStateStore(app.sql, 'main', schema),
      peer: createPostgresSecurityStateStore(app.sql, 'main', schema),
      close,
    };
  } catch (error) {
    await close();
    throw error;
  }
}
