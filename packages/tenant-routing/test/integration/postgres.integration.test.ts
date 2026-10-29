// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createApplication, type Application } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { tenantRegistrySqlProvider } from '../../dist/index.js';
import { registryContentChecksum } from '../../dist/registry.js';
import { fixture as httpFixture, settings as routingSettings, send } from '../http-fixture.js';

if (process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1' || !process.env.ARKENIVA_POSTGRES_URL)
  throw new Error(
    'Tenant registry PostgreSQL tests require an explicitly disposable verified endpoint',
  );

function content(changed: boolean) {
  const body = {
    schemaVersion: '1.1.0' as const,
    operations: [],
    bindings: [],
    implementations: changed
      ? [{ id: 'installed', kind: 'handler' as const, handlerKey: 'local' }]
      : [],
  };
  return { body: JSON.stringify(body), checksum: registryContentChecksum(body) };
}
async function application(main = false): Promise<Application> {
  const app = await createApplication({
    service: { name: 'tenant-registry-integration', version: '1.0.0', environment: 'test' },
    plugins: [postgresPlugin()],
    databases: {
      control: { driver: 'postgresql', connectionStringEnv: 'ARKENIVA_POSTGRES_URL', poolMax: 2 },
      ...(main
        ? {
            main: {
              driver: 'postgresql' as const,
              connectionStringEnv: 'ARKENIVA_POSTGRES_URL',
              poolMax: 1,
            },
          }
        : {}),
    },
  });
  await app.start();
  return app;
}

test(
  'Two real applications read atomic SQL activations, immutable revisions and CAS-controlled rollback',
  { timeout: 30000 },
  async () => {
    const first = await application(true),
      second = await application();
    const schema = 'tr_' + randomBytes(12).toString('hex');
    assert.match(schema, /^tr_[0-9a-f]{24}$/);
    const prefix = schema + '.tenant_registry',
      blue = content(false),
      green = content(true);
    const settings = {
      connectionName: 'control',
      storageKey: 'control',
      storagePrefixes: { control: prefix },
    };
    let release: () => void = () => {};
    let routed: Awaited<ReturnType<typeof httpFixture>> | undefined;
    try {
      const nativePool = first.sql.native('control'),
        mainOperations = first.sql.stats('main').operations;
      await first.sql.execute('control', { text: `CREATE SCHEMA ${schema}` });
      await first.sql.execute('control', {
        text: `CREATE TABLE ${prefix}_snapshot (revision_key varchar(128) PRIMARY KEY, content_checksum varchar(71) NOT NULL, body text NOT NULL)`,
      });
      await first.sql.execute('control', {
        text: `CREATE TABLE ${prefix}_active (registry_key varchar(16) PRIMARY KEY, activation_generation bigint NOT NULL CHECK (activation_generation > 0), revision_key varchar(128) NOT NULL REFERENCES ${prefix}_snapshot(revision_key), activated_at timestamptz NOT NULL)`,
      });
      await first.sql.execute('control', {
        text: `CREATE FUNCTION ${schema}.immutable_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Immutable registry content'; END $$`,
      });
      await first.sql.execute('control', {
        text: `CREATE TRIGGER immutable_content BEFORE UPDATE OR DELETE ON ${prefix}_snapshot FOR EACH ROW EXECUTE FUNCTION ${schema}.immutable_snapshot()`,
      });
      for (const [revision, value] of [
        ['blue', blue],
        ['green', green],
      ] as const)
        await first.sql.execute('control', {
          text: `INSERT INTO ${prefix}_snapshot VALUES (:revision, :checksum, :body)`,
          bindings: { revision, checksum: value.checksum, body: value.body },
        });
      await first.sql.execute('control', {
        text: `INSERT INTO ${prefix}_active VALUES ('active', 1, 'blue', CURRENT_TIMESTAMP)`,
      });
      let metadataEffects = 0;
      for (const sql of [first.sql, second.sql])
        for (const key of ['bind', 'name', 'length'])
          Object.defineProperty(sql.transaction, key, {
            get() {
              metadataEffects++;
              throw new Error('SQL callback metadata must not execute');
            },
          });
      const provider = tenantRegistrySqlProvider({ ...settings, sql: first.sql }),
        other = tenantRegistrySqlProvider({ ...settings, sql: second.sql });
      const original = await provider.loadSnapshot();
      assert.equal(metadataEffects, 0);
      assert.equal(original.revision, 'blue');
      assert.equal(original.activationGeneration, 1);
      let applicationOwner: Application | undefined,
        loads = 0;
      routed = await httpFixture(
        {
          ...routingSettings(),
          registry: {
            async loadSnapshot(options) {
              loads++;
              assert.ok(applicationOwner);
              return tenantRegistrySqlProvider({
                ...settings,
                sql: applicationOwner.sql,
              }).loadSnapshot(options);
            },
          },
        },
        {
          plugins: [postgresPlugin()],
          databases: {
            control: {
              driver: 'postgresql',
              connectionStringEnv: 'ARKENIVA_POSTGRES_URL',
              poolMax: 2,
            },
          },
          onCreated: (app) => {
            applicationOwner = app;
          },
        },
      );
      assert.equal(
        (
          await send(routed.origin, '/api/tenant/capabilities', {
            headers: { authorization: await routed.token() },
          })
        ).json().revision,
        'blue',
      );

      let staged!: () => void;
      const ready = new Promise<void>((resolve) => {
          staged = resolve;
        }),
        gate = new Promise<void>((resolve) => {
          release = resolve;
        });
      const promotion = second.sql.transaction('control', async (tx) => {
        const result = await tx.execute({
          text: `UPDATE ${prefix}_active SET activation_generation = 2, revision_key = 'green', activated_at = CURRENT_TIMESTAMP WHERE registry_key = 'active' AND activation_generation = 1`,
        });
        assert.equal(result.metadata.affectedRows, 1);
        staged();
        await gate;
      });
      // Retain the rejection handler while the deliberate open transaction is observed.
      const settled = promotion.then(
        () => ({ ok: true as const }),
        (error) => ({ ok: false as const, error }),
      );
      try {
        await Promise.race([ready, promotion]);
        const concurrent = await provider.loadSnapshot();
        assert.equal(concurrent.revision, 'blue');
        assert.equal(concurrent.activationGeneration, 1);
      } finally {
        release();
      }
      const outcome = await settled;
      if (!outcome.ok) throw outcome.error;
      const active = await provider.loadSnapshot();
      assert.equal(active.revision, 'green');
      assert.equal(active.activationGeneration, 2);
      const stillOriginal = await send(routed.origin, '/api/tenant/capabilities', {
        headers: { authorization: await routed.token() },
      });
      assert.equal(stillOriginal.json().revision, 'blue');
      assert.equal(stillOriginal.json().activationGeneration, 1);
      assert.equal(loads, 1);
      assert.equal((await other.loadSnapshot()).revision, 'green');
      assert.equal(original.revision, 'blue');
      assert.equal(original.implementations.length, 0);
      await assert.rejects(
        first.sql.execute('control', {
          text: `UPDATE ${prefix}_snapshot SET body = '{}' WHERE revision_key = 'blue'`,
        }),
        { code: 'EK_DATABASE_QUERY' },
      );

      await first.sql.execute('control', {
        text: `UPDATE ${prefix}_active SET activation_generation = 3, revision_key = 'blue', activated_at = CURRENT_TIMESTAMP WHERE registry_key = 'active' AND activation_generation = 2`,
      });
      assert.equal((await provider.loadSnapshot()).revision, 'blue');
      assert.equal(active.revision, 'green');
      const races = await Promise.all(
        [first, second].map((app, index) =>
          app.sql.transaction('control', (tx) =>
            tx.execute({
              text: `UPDATE ${prefix}_active SET activation_generation = 4, revision_key = :revision, activated_at = CURRENT_TIMESTAMP WHERE registry_key = 'active' AND activation_generation = 3`,
              bindings: { revision: index ? 'green' : 'blue' },
            }),
          ),
        ),
      );
      assert.equal(
        races.reduce((sum, result) => sum + (result.metadata.affectedRows ?? 0), 0),
        1,
      );
      assert.equal((await provider.loadSnapshot()).activationGeneration, 4);

      await first.sql.execute('control', {
        text: `INSERT INTO ${prefix}_snapshot VALUES ('tampered', :checksum, :body)`,
        bindings: { checksum: 'sha256:' + '0'.repeat(64), body: blue.body },
      });
      await first.sql.execute('control', {
        text: `UPDATE ${prefix}_active SET activation_generation = 5, revision_key = 'tampered', activated_at = CURRENT_TIMESTAMP WHERE registry_key = 'active'`,
      });
      await assert.rejects(provider.loadSnapshot(), { code: 'EK_TROUTE_REGISTRY' });
      await first.sql.execute('control', {
        text: `INSERT INTO ${prefix}_snapshot VALUES ('oversized', :checksum, repeat('x', 8388609))`,
        bindings: { checksum: blue.checksum },
      });
      await first.sql.execute('control', {
        text: `UPDATE ${prefix}_active SET activation_generation = 6, revision_key = 'oversized', activated_at = CURRENT_TIMESTAMP WHERE registry_key = 'active'`,
      });
      await assert.rejects(provider.loadSnapshot(), { code: 'EK_TROUTE_REGISTRY' });

      await first.sql.execute('control', {
        text: `UPDATE ${prefix}_active SET activation_generation = :maximum, revision_key = 'blue', activated_at = CURRENT_TIMESTAMP WHERE registry_key = 'active'`,
        bindings: { maximum: String(Number.MAX_SAFE_INTEGER) },
      });
      assert.equal((await provider.loadSnapshot()).activationGeneration, Number.MAX_SAFE_INTEGER);
      await first.sql.execute('control', {
        text: `UPDATE ${prefix}_active SET activation_generation = activation_generation + 1 WHERE registry_key = 'active'`,
      });
      await assert.rejects(provider.loadSnapshot(), { code: 'EK_TROUTE_REGISTRY' });
      await assert.rejects(
        tenantRegistrySqlProvider({
          ...settings,
          sql: first.sql,
          connectionName: 'missing',
        }).loadSnapshot(),
        { code: 'EK_TROUTE_REGISTRY' },
      );
      assert.equal(first.sql.native('control'), nativePool);
      assert.equal(first.sql.stats('main').operations, mainOperations);
      await second.stop();
      await assert.rejects(other.loadSnapshot(), { code: 'EK_TROUTE_REGISTRY' });
    } finally {
      release();
      await routed?.close();
      try {
        await first.sql.execute('control', { text: `DROP SCHEMA IF EXISTS ${schema} CASCADE` });
      } finally {
        await Promise.allSettled([first.stop(), second.stop()]);
      }
    }
  },
);
