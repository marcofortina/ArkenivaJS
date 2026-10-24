import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { setTimeout as pause } from 'node:timers/promises';
import type { Pool, PoolClient } from 'pg';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application, SqlTransaction, Plugin } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';

const endpoint = process.env.ARKENIVA_POSTGRES_URL;
const wrongSan = process.env.ARKENIVA_POSTGRES_WRONG_SAN_URL;
if (!endpoint || !wrongSan || process.env.ARKENIVA_POSTGRES_DISPOSABLE !== '1')
  throw new Error(
    'Real PostgreSQL integration requires explicit disposable endpoints and ARKENIVA_POSTGRES_DISPOSABLE=1',
  );
const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;

const nativeCode = (error: unknown, expected: readonly string[]): boolean => {
  let current = error;
  for (let depth = 0; depth < 10 && current && typeof current === 'object'; depth++) {
    if ('code' in current && typeof current.code === 'string' && expected.includes(current.code))
      return true;
    current = 'cause' in current ? current.cause : undefined;
  }
  return false;
};

async function started(
  url = endpoint!,
  poolMax = 2,
  secondary = false,
  plugin: Plugin = postgresPlugin(),
): Promise<Application> {
  const variable = 'ARKENIVA_PG_LIVE_' + randomBytes(12).toString('hex').toUpperCase();
  process.env[variable] = url;
  let app: Application | undefined;
  try {
    app = await createApplication({
      service: { name: 'postgres-integration', version: '1.0.0', environment: 'test' },
      plugins: [plugin],
      databases: {
        main: { driver: 'postgresql', connectionStringEnv: variable, poolMax },
        ...(secondary
          ? { secondary: { driver: 'postgresql' as const, connectionStringEnv: variable, poolMax } }
          : {}),
      },
    });
    await app.start();
    return app;
  } catch (cause) {
    await app?.stop();
    throw cause;
  } finally {
    delete process.env[variable];
  }
}

async function schemaFixture() {
  const app = await started();
  const schema = 'ak_' + randomBytes(12).toString('hex');
  // Identifiers come only from this bounded hexadecimal allowlist, never request data.
  assert.match(schema, /^[a-z][a-z0-9_]{0,62}$/);
  try {
    await app.sql.execute('main', { text: `CREATE SCHEMA ${schema}` });
  } catch (cause) {
    await app.stop();
    throw cause;
  }
  return {
    app,
    schema,
    async close() {
      try {
        await app.sql.execute('main', { text: `DROP SCHEMA ${schema} CASCADE` });
      } finally {
        await app.stop();
      }
    },
  };
}

async function eventually(check: () => boolean | Promise<boolean>): Promise<void> {
  const until = performance.now() + 5000;
  while (!(await check())) {
    if (performance.now() >= until)
      throw new Error('PostgreSQL integration condition did not settle');
    await pause(5);
  }
}

test('EK-DB-001 live PostgreSQL uses verified TLS and a non-superuser with exact scalar, binary and temporal values', async () => {
  const app = await started();
  try {
    const role = await app.sql.queryOne<{
      rolsuper: boolean;
      rolcreatedb: boolean;
      rolcreaterole: boolean;
    }>('main', {
      text: 'SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user',
    });
    assert.deepEqual(role, { rolsuper: false, rolcreatedb: false, rolcreaterole: false });
    const result = await app.sql.query('main', {
      text: `SELECT :id::bigint AS id, :decimal::numeric AS decimal, :bytes::bytea AS bytes, :time::timestamptz AS time, :json::jsonb AS json, :zero::int AS zero, :nil::text AS nil, :yes::boolean AS yes`,
      bindings: {
        id: 9007199254740993123n,
        decimal: '12345678901234567890.123456789',
        bytes: new Uint8Array([0, 255, 17]),
        time: '2026-10-24T12:13:14.123456Z',
        json: '{"count":9007199254740993}',
        zero: 0,
        nil: null,
        yes: true,
      },
    });
    assert.equal(result.rowCount, 1);
    assert.equal(result.rows.length, 1);
    const row = result.rows[0]!;
    // PostgreSQL bigint itself is signed 64-bit; the exercised value below remains in range.
    assert.equal(row.id, '9007199254740993123');
    assert.equal(row.decimal, '12345678901234567890.123456789');
    assert.deepEqual([...(row.bytes as Uint8Array)], [0, 255, 17]);
    assert.match(row.time as string, /2026-10-24 12:13:14\.123456\+00/);
    assert.match(row.json as string, /9007199254740993/);
    assert.equal(row.zero, 0);
    assert.equal(row.nil, null);
    assert.equal(row.yes, true);
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 live bind lexing ignores comments and dollar quotes, repeats names, and treats injection as data', async () => {
  const app = await started();
  try {
    const result = await app.sql.queryOne('main', {
      text: "SELECT :id::int AS a, :id::int AS b, $$:hidden$$ AS body, ':also_hidden' AS literal /* :comment */",
      bindings: { id: 7 },
    });
    assert.deepEqual(result, { a: 7, b: 7, body: ':hidden', literal: ':also_hidden' });
    const hostile = "'; SELECT pg_sleep(10); -- :other";
    assert.deepEqual(
      await app.sql.queryOne('main', {
        text: 'SELECT :value::text AS value',
        bindings: { value: hostile },
      }),
      { value: hostile },
    );
    const before = app.sql.stats('main').operations!;
    await assert.rejects(
      app.sql.query('main', { text: 'SELECT :missing' }),
      code('EK_CONFIG_INVALID'),
    );
    await assert.rejects(
      app.sql.query('main', { text: 'SELECT :id', bindings: { id: 1, extra: 2 } }),
      code('EK_CONFIG_INVALID'),
    );
    assert.equal(app.sql.stats('main').operations, before);
    await assert.rejects(
      app.sql.execute('main', { text: '/* outer /* nested */ still outer */ BEGIN' }),
      code('EK_DATABASE_TRANSACTION'),
    );
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 live cursors return empty/one rows and reject excess rows without partial success', async () => {
  const app = await started();
  try {
    assert.equal(await app.sql.queryOne('main', { text: 'SELECT 1 WHERE false' }), null);
    assert.deepEqual(await app.sql.queryOne('main', { text: 'SELECT 1 AS one' }), { one: 1 });
    await assert.rejects(
      app.sql.queryOne('main', { text: 'SELECT generate_series(1,2)' }),
      code('EK_DATABASE_QUERY'),
    );
    const bounded = await app.sql.query(
      'main',
      { text: 'SELECT generate_series(1,300) AS id' },
      { maxRows: 300 },
    );
    assert.equal(bounded.rows.length, 300);
    assert.equal(bounded.rowCount, null);
    await assert.rejects(
      app.sql.query('main', { text: 'SELECT generate_series(1,1000000)' }, { maxRows: 10 }),
      (error: unknown) =>
        code('EK_DATABASE_QUERY')(error) && (error as KitError).details?.limitExceeded === true,
    );
    assert.equal(await app.sql.ping('main'), true);
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 live RETURNING, constraint classification, commit and rollback preserve native effects', async () => {
  const fixture = await schemaFixture();
  const { app, schema } = fixture;
  try {
    await app.sql.execute('main', {
      text: `CREATE TABLE ${schema}.items(id BIGINT PRIMARY KEY, value TEXT NOT NULL)`,
    });
    const write = await app.sql.execute('main', {
      text: `INSERT INTO ${schema}.items VALUES (:id,:value) RETURNING id`,
      bindings: { id: 1n, value: 'first' },
    });
    assert.equal(write.rowCount, 1);
    assert.equal(write.metadata.affectedRows, 1);
    assert.deepEqual(write.rows, [{ id: '1' }]);
    await assert.rejects(
      app.sql.execute('main', {
        text: `INSERT INTO ${schema}.items VALUES (:id,:value)`,
        bindings: { id: 1n, value: 'private-row' },
      }),
      (error: unknown) => {
        assert.ok(code('EK_DATABASE_CONSTRAINT')(error));
        assert.equal((error as KitError).details?.sqlState, '23505');
        assert.ok(!JSON.stringify(error).includes('private-row'));
        return true;
      },
    );
    const primary = new Error('application rollback request');
    await assert.rejects(
      app.sql.transaction('main', async (tx) => {
        await tx.execute({
          text: `INSERT INTO ${schema}.items VALUES (:id,:value)`,
          bindings: { id: 2n, value: 'rollback' },
        });
        throw primary;
      }),
      (error) => error === primary,
    );
    assert.equal(
      await app.sql.queryOne('main', {
        text: `SELECT id FROM ${schema}.items WHERE id=:id`,
        bindings: { id: 2n },
      }),
      null,
    );
    assert.equal(
      await app.sql.transaction('main', async (tx) => {
        await tx.execute({
          text: `INSERT INTO ${schema}.items VALUES (:id,:value)`,
          bindings: { id: 3n, value: 'committed' },
        });
        return 42;
      }),
      42,
    );
    assert.deepEqual(
      await app.sql.queryOne('main', {
        text: `SELECT id FROM ${schema}.items WHERE id=:id`,
        bindings: { id: 3n },
      }),
      { id: '3' },
    );
  } finally {
    await fixture.close();
  }
});

test('EK-CORE-002 live transactions pin one backend, serialize parallel statements and keep application pools isolated', async () => {
  const plugin = postgresPlugin();
  const first = await started(endpoint!, 2, true, plugin);
  const second = await started(endpoint!, 2, false, plugin);
  let captured!: SqlTransaction;
  try {
    assert.notEqual(first.sql.native('main'), second.sql.native('main'));
    assert.notEqual(first.sql.native('main'), first.sql.native('secondary'));
    await first.sql.transaction('main', async (tx) => {
      captured = tx;
      const pid = (await tx.query<{ pid: number }>({ text: 'SELECT pg_backend_pid() AS pid' }))
        .rows[0]!.pid;
      const values = await Promise.all([
        tx.query({ text: 'SELECT pg_backend_pid() AS pid' }),
        tx.query({ text: 'SELECT pg_backend_pid() AS pid' }),
      ]);
      for (const result of values) assert.equal(result.rows[0]!.pid, pid);
      await assert.rejects(
        first.sql.query('main', { text: 'SELECT 1' }),
        code('EK_DATABASE_TRANSACTION'),
      );
      await assert.rejects(
        first.sql.transaction('secondary', async () => undefined),
        code('EK_DATABASE_TRANSACTION'),
      );
    });
    await assert.rejects(captured.execute({ text: 'SELECT 1' }), code('EK_DATABASE_TRANSACTION'));
    await first.stop();
    assert.equal(await second.sql.ping('main'), true);
  } finally {
    await first.stop();
    await second.stop();
  }
});

test('EK-DB-001 live queued statements snapshot mutable values and compile with the actual transaction string mode', async () => {
  const app = await started();
  try {
    await app.sql.transaction('main', async (tx) => {
      const date = new Date('2026-10-24T00:00:00Z');
      const bytes = new Uint8Array([1, 2]);
      const changing = tx.execute({ text: 'SET LOCAL standard_conforming_strings TO off' });
      const query = tx.query({
        text: "SELECT 'escaped\\' :hidden'::text AS escaped, :date::timestamptz AS date, :bytes::bytea AS bytes",
        bindings: { date, bytes },
      });
      date.setTime(0);
      bytes[0] = 9;
      await changing;
      const result = await query;
      assert.equal(result.rows[0]!.escaped, "escaped' :hidden");
      assert.match(result.rows[0]!.date as string, /^2026-10-24/);
      assert.deepEqual([...(result.rows[0]!.bytes as Uint8Array)], [1, 2]);
    });
    assert.deepEqual(
      await app.sql.queryOne('main', { text: "SELECT 'ordinary\\'::text AS value" }),
      { value: 'ordinary\\' },
    );
  } finally {
    await app.stop();
  }
});

test('EK-CORE-001 live pool cancellation releases late acquisitions without executing abandoned statements', async () => {
  const app = await started(endpoint!, 1);
  const pool = app.sql.native('main') as Pool;
  const held = await pool.connect();
  const controller = new AbortController();
  try {
    const before = app.sql.stats('main').operations;
    const query = app.sql.query('main', { text: 'SELECT 1' }, { signal: controller.signal });
    await eventually(() => app.sql.stats('main').waiting === 1);
    controller.abort();
    await assert.rejects(query, code('EK_ABORTED'));
    held.release();
    await eventually(() => app.sql.stats('main').pendingAcquires === 0);
    assert.equal(app.sql.stats('main').operations, before);
    assert.equal(await app.sql.ping('main'), true);
  } finally {
    if (!controller.signal.aborted) held.release();
    await app.stop();
  }
});

test('EK-CORE-001 live query timeout discards the active connection and never retries the statement', async () => {
  const app = await started();
  try {
    const before = app.sql.stats('main').operations!;
    await assert.rejects(
      app.sql.query('main', { text: 'SELECT pg_sleep(5)' }, { timeoutMs: 100 }),
      code('EK_TIMEOUT'),
    );
    assert.equal(app.sql.stats('main').operations, before + 1);
    assert.equal(await app.sql.ping('main'), true);
  } finally {
    await app.stop();
  }
});

test('EK-SEC-001 live PostgreSQL rejects wrong certificate identity, untrusted issuer and invalid credentials', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkeniva-pg-negative-ca-'));
  try {
    await assert.rejects(started(wrongSan!), (error) =>
      nativeCode(error, ['ERR_TLS_CERT_ALTNAME_INVALID']),
    );
    const certificate = join(directory, 'untrusted.crt');
    await promisify(execFile)('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-subj',
      '/CN=Untrusted test CA',
      '-keyout',
      join(directory, 'untrusted.key'),
      '-out',
      certificate,
    ]);
    const untrusted = new URL(endpoint!);
    untrusted.searchParams.set('sslrootcert', certificate);
    await assert.rejects(started(untrusted.href), (error) =>
      nativeCode(error, ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY']),
    );
    const wrongPassword = new URL(endpoint!);
    wrongPassword.password = randomBytes(24).toString('hex');
    await assert.rejects(started(wrongPassword.href), (error: unknown) => {
      assert.ok(error instanceof KitError);
      assert.ok(nativeCode(error, ['28P01']));
      assert.ok(!JSON.stringify(error).includes(wrongPassword.password));
      return true;
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('EK-DB-001 a native acknowledgment fault after a real commit reports unknown outcome without replay', async () => {
  const fixture = await schemaFixture();
  const { app, schema } = fixture;
  let callbacks = 0;
  try {
    await app.sql.execute('main', {
      text: `CREATE TABLE ${schema}.commits(id INTEGER PRIMARY KEY)`,
    });
    const pool = app.sql.native('main') as Pool;
    const patch = (client: PoolClient) => {
      const original = client.query.bind(client) as (...args: unknown[]) => unknown;
      client.query = ((...args: unknown[]) => {
        if (args[0] !== 'COMMIT') return original(...args);
        return Promise.resolve(original(...args)).then(() => {
          throw Object.assign(new Error('Injected native commit acknowledgment loss'), {
            code: 'ECONNRESET',
          });
        });
      }) as PoolClient['query'];
    };
    pool.once('acquire', patch);
    await assert.rejects(
      app.sql.transaction('main', async (tx) => {
        callbacks++;
        await tx.execute({ text: `INSERT INTO ${schema}.commits VALUES (1)` });
      }),
      (error: unknown) =>
        code('EK_DATABASE_TRANSACTION')(error) &&
        (error as KitError).details?.outcome === 'unknown',
    );
    assert.equal(callbacks, 1);
    assert.deepEqual(
      await app.sql.queryOne('main', {
        text: `SELECT count(*)::int AS count FROM ${schema}.commits`,
      }),
      { count: 1 },
    );
  } finally {
    await fixture.close();
  }
});

test('EK-DB-001 native named statements remain usable after a portable checkout resets session state', async () => {
  const app = await started(endpoint!, 1);
  try {
    const pool = app.sql.native('main') as Pool;
    const prepared = { name: 'integration-named-statement', text: 'SELECT $1::int AS value' };
    assert.deepEqual((await pool.query({ ...prepared, values: [1] })).rows, [{ value: 1 }]);
    await app.sql.query('main', { text: 'SELECT 1' });
    assert.deepEqual((await pool.query({ ...prepared, values: [2] })).rows, [{ value: 2 }]);
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 live multi-batch RETURNING omits unreliable counts and preserves every returned row', async () => {
  const fixture = await schemaFixture();
  const { app, schema } = fixture;
  try {
    await app.sql.execute('main', { text: `CREATE TABLE ${schema}.bulk(id INTEGER PRIMARY KEY)` });
    const result = await app.sql.execute('main', {
      text: `INSERT INTO ${schema}.bulk SELECT generate_series(1,300) RETURNING id`,
    });
    assert.equal(result.rows.length, 300);
    assert.equal(result.rowCount, null);
    assert.equal(result.metadata.affectedRows, undefined);
    assert.deepEqual(
      await app.sql.queryOne('main', { text: `SELECT count(*)::int AS count FROM ${schema}.bulk` }),
      { count: 300 },
    );
    const changed = await app.sql.execute('main', { text: `UPDATE ${schema}.bulk SET id=id+1000` });
    assert.equal(changed.rowCount, 300);
    assert.equal(changed.metadata.affectedRows, 300);
  } finally {
    await fixture.close();
  }
});

test('EK-DB-001 a real backend termination during deferred COMMIT reports an unknown outcome without replay', async () => {
  const fixture = await schemaFixture();
  const { app, schema } = fixture;
  const controller = new AbortController();
  let resolvePid!: (pid: number) => void,
    callbacks = 0;
  const ready = new Promise<number>((resolve) => {
    resolvePid = resolve;
  });
  let transaction: Promise<void> | undefined;
  try {
    await app.sql.execute('main', {
      text: `CREATE TABLE ${schema}.interrupted(id INTEGER PRIMARY KEY)`,
    });
    await app.sql.execute('main', {
      text: `CREATE FUNCTION ${schema}.wait_at_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(10); RETURN NEW; END; $$`,
    });
    await app.sql.execute('main', {
      text: `CREATE CONSTRAINT TRIGGER delay_commit AFTER INSERT ON ${schema}.interrupted DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ${schema}.wait_at_commit()`,
    });
    transaction = app.sql.transaction(
      'main',
      async (tx) => {
        callbacks++;
        const pid = (await tx.query<{ pid: number }>({ text: 'SELECT pg_backend_pid() AS pid' }))
          .rows[0]!.pid;
        await tx.execute({ text: `INSERT INTO ${schema}.interrupted VALUES (1)` });
        resolvePid(pid);
      },
      { signal: controller.signal, timeoutMs: 10000 },
    );
    const rejected = assert.rejects(
      transaction,
      (error: unknown) =>
        code('EK_DATABASE_TRANSACTION')(error) &&
        (error as KitError).details?.outcome === 'unknown',
    );
    void rejected.catch(() => undefined);
    const pid = await Promise.race([
      ready,
      transaction.then(() => {
        throw new Error('Transaction finished before publishing its backend');
      }),
    ]);
    await eventually(async () =>
      Boolean(
        await app.sql.queryOne('main', {
          text: "SELECT pid FROM pg_stat_activity WHERE pid=:pid AND state='active' AND query='COMMIT'",
          bindings: { pid },
        }),
      ),
    );
    assert.deepEqual(
      await app.sql.queryOne('main', {
        text: 'SELECT pg_terminate_backend(:pid) AS terminated',
        bindings: { pid },
      }),
      { terminated: true },
    );
    await rejected;
    assert.equal(callbacks, 1);
    assert.deepEqual(
      await app.sql.queryOne('main', {
        text: `SELECT count(*)::int AS count FROM ${schema}.interrupted`,
      }),
      { count: 0 },
    );
  } finally {
    controller.abort();
    if (transaction) await Promise.allSettled([transaction]);
    await fixture.close();
  }
});
