import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setTimeout as pause } from 'node:timers/promises';
import type { Pool, PoolConnection } from 'mysql2';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application, Plugin, SqlTransaction } from '@arkenivajs/core';
import { mysqlPlugin } from '@arkenivajs/database-mysql';

const endpoint = process.env.ARKENIVA_MYSQL_URL;
const wrongSan = process.env.ARKENIVA_MYSQL_WRONG_SAN_URL;
if (!endpoint || !wrongSan || process.env.ARKENIVA_MYSQL_DISPOSABLE !== '1')
  throw new Error(
    'Real MySQL integration requires explicit disposable TLS endpoints and ARKENIVA_MYSQL_DISPOSABLE=1',
  );

const code =
  (expected: string) =>
  (error: unknown): boolean =>
    error instanceof KitError && error.code === expected;
const nativeCode = (
  error: unknown,
  expected: readonly string[],
  inspect: (error: object) => boolean = () => true,
): boolean => {
  let current = error;
  for (let depth = 0; depth < 10 && current && typeof current === 'object'; depth++) {
    if (
      'code' in current &&
      typeof current.code === 'string' &&
      expected.includes(current.code) &&
      inspect(current)
    )
      return true;
    current = 'cause' in current ? current.cause : undefined;
  }
  return false;
};
async function started(
  url = endpoint!,
  poolMax = 2,
  plugin: Plugin = mysqlPlugin(),
  secondary = false,
  poolMin = 0,
): Promise<Application> {
  const variable = 'ARKENIVA_MYSQL_LIVE_' + randomBytes(12).toString('hex').toUpperCase();
  process.env[variable] = url;
  let app: Application | undefined;
  try {
    app = await createApplication({
      service: { name: 'mysql-integration', version: '1.0.0', environment: 'test' },
      plugins: [plugin],
      databases: {
        main: { driver: 'mysql', connectionStringEnv: variable, poolMax, poolMin },
        ...(secondary
          ? { secondary: { driver: 'mysql' as const, connectionStringEnv: variable, poolMax } }
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
async function fixture() {
  const app = await started();
  const table = 'ak_' + randomBytes(12).toString('hex');
  // Only this bounded random hexadecimal allowlist supplies SQL identifiers.
  assert.match(table, /^[a-z][a-z0-9_]{0,63}$/);
  await app.sql.execute('main', {
    text: `CREATE TABLE ${table} (id BIGINT PRIMARY KEY, value INT NOT NULL) ENGINE=InnoDB`,
  });
  return {
    app,
    table,
    async close() {
      try {
        await app.sql.execute('main', { text: `DROP TABLE IF EXISTS ${table}` });
      } finally {
        await app.stop();
      }
    },
  };
}
async function borrowed(pool: Pool): Promise<PoolConnection> {
  return new Promise((resolve, reject) =>
    pool.getConnection((error, client) => (error ? reject(error) : resolve(client))),
  );
}
async function eventually(check: () => boolean): Promise<void> {
  const until = performance.now() + 5000;
  while (!check()) {
    if (performance.now() >= until) throw new Error('MySQL cleanup did not settle');
    await pause(5);
  }
}

test('EK-SEC-001 live MySQL authenticates a scoped account with verified TLS and explicit UTC/UTF-8', async () => {
  const app = await started(endpoint, 2, mysqlPlugin(), false, 2);
  try {
    const settings = await app.sql.queryOne('main', {
      text: 'SELECT VERSION() AS version, CURRENT_USER() AS account, @@session.time_zone AS zone, @@session.character_set_client AS encoding',
    });
    assert.match(String(settings?.version), /^9\.7\.4/);
    assert.equal(settings?.account, 'arkeniva_app@%');
    assert.equal(settings?.zone, '+00:00');
    assert.equal(settings?.encoding, 'utf8mb4');
    const tls = await app.sql.query('main', { text: "SHOW SESSION STATUS LIKE 'Ssl_cipher'" });
    assert.ok(String(tls.rows[0]?.Value).length > 0);
    const grants = await app.sql.query('main', { text: 'SHOW GRANTS FOR CURRENT_USER' });
    const text = grants.rows.map((row) => String(Object.values(row)[0])).join('\n');
    assert.match(text, /GRANT USAGE ON \*\.\*/);
    assert.match(text, /ON `arkeniva_test`\.\*/);
    assert.doesNotMatch(text, /GRANT (?:ALL|CREATE USER|SUPER).*ON \*\.\*/);
    assert.equal(await app.sql.ping('main'), true);
    const stats = app.sql.stats('main');
    assert.equal(stats.total, null);
    assert.equal(stats.idle, null);
    assert.equal(stats.waiting, null);
    assert.equal(stats.active, 0);
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 live MySQL binds repeated names, hostile Unicode and injection as independent values', async () => {
  const app = await started();
  try {
    const payload = "😀'; DROP TABLE forbidden; -- :fake";
    const row = await app.sql.queryOne('main', {
      text: "SELECT ':ignored' AS literal, :value AS left_value, :value AS right_value /* :comment */ # :line\n",
      bindings: { value: payload },
    });
    assert.deepEqual(row, { literal: ':ignored', left_value: payload, right_value: payload });
    const before = app.sql.stats('main').operations;
    for (const statement of [
      { text: 'SELECT :missing' },
      { text: 'SELECT :a', bindings: { a: 1, extra: 2 } },
      { text: 'SELECT /*! :hidden */ 1' },
      { text: 'SELECT ?', bindings: { a: 1 } },
    ])
      await assert.rejects(app.sql.query('main', statement), code('EK_CONFIG_INVALID'));
    for (const text of [
      'COMMIT',
      '# ignored\n START TRANSACTION',
      '/* prefix */ ROLLBACK',
      '-- ignored\n SAVEPOINT a',
      'CALL procedure_name()',
    ])
      await assert.rejects(app.sql.execute('main', { text }), code('EK_DATABASE_TRANSACTION'));
    assert.equal(app.sql.stats('main').operations, before);
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 live MySQL preserves bigint, decimal, JSON, microseconds, BLOB, null and exact insert identifiers', async () => {
  const { app, table, close } = await fixture();
  const typed = table + '_typed';
  try {
    await app.sql.execute('main', {
      text: `CREATE TABLE ${typed} (id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT, amount DECIMAL(40,16), payload BLOB, optional_value INT, stamp DATETIME(6), doc JSON, flag TINYINT) ENGINE=InnoDB AUTO_INCREMENT=9007199254740993`,
    });
    const written = await app.sql.execute('main', {
      text: `INSERT INTO ${typed} (amount,payload,optional_value,stamp,doc,flag) VALUES (:amount,:payload,:optional,:stamp,:doc,:flag)`,
      bindings: {
        amount: '12345678901234567890.1234567890123456',
        payload: new Uint8Array([0, 255, 1]),
        optional: null,
        stamp: '2026-10-25 01:02:03.123456',
        doc: '{"id":9007199254740993}',
        flag: false,
      },
    });
    assert.equal(String(written.metadata.insertId), '9007199254740993');
    assert.equal(written.metadata.affectedRows, 1);
    assert.equal(written.rowCount, 1);
    assert.deepEqual(written.rows, []);
    const row = await app.sql.queryOne('main', {
      text: `SELECT * FROM ${typed} WHERE id=:id`,
      bindings: { id: 9007199254740993n },
    });
    assert.equal(row?.id, '9007199254740993');
    assert.equal(row?.amount, '12345678901234567890.1234567890123456');
    assert.deepEqual(row?.payload, Buffer.from([0, 255, 1]));
    assert.equal(row?.optional_value, null);
    assert.equal(row?.stamp, '2026-10-25 01:02:03.123456');
    assert.match(String(row?.doc), /9007199254740993/);
    assert.equal(row?.flag, 0);
  } finally {
    try {
      await app.sql.execute('main', { text: `DROP TABLE IF EXISTS ${typed}` });
    } finally {
      await close();
    }
  }
});

test('EK-DB-001 live MySQL streams bounded results and rejects queryOne on the second row', async () => {
  const app = await started();
  try {
    assert.equal(await app.sql.queryOne('main', { text: 'SELECT 1 WHERE 1=0' }), null);
    assert.equal((await app.sql.query('main', { text: 'SELECT 1 WHERE 1=0' })).rowCount, 0);
    assert.deepEqual(await app.sql.queryOne('main', { text: 'SELECT 1 AS value' }), { value: '1' });
    await assert.rejects(
      app.sql.queryOne('main', { text: 'SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3' }),
      code('EK_DATABASE_QUERY'),
    );
    const text =
      'WITH RECURSIVE numbers AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM numbers WHERE n<300) SELECT n FROM numbers';
    const rows = await app.sql.query('main', { text }, { maxRows: 300 });
    assert.equal(rows.rows.length, 300);
    assert.equal(rows.rowCount, 300);
    await assert.rejects(
      app.sql.query('main', { text }, { maxRows: 257 }),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_DATABASE_QUERY' &&
        error.details?.limitExceeded === true,
    );
    for (const maxRows of [0, -1, 100001, 1.5])
      await assert.rejects(app.sql.query('main', { text }, { maxRows }), code('EK_CONFIG_INVALID'));
    assert.equal(await app.sql.ping('main'), true);
  } finally {
    await app.stop();
  }
});

test('EK-DB-001 live MySQL commits once, rolls back callback failures and classifies actual duplicate key 1062', async () => {
  const { app, table, close } = await fixture();
  let calls = 0;
  try {
    assert.equal(
      await app.sql.transaction('main', async (tx) => {
        calls++;
        await tx.execute({
          text: `INSERT INTO ${table} VALUES (:id,:value)`,
          bindings: { id: 1n, value: 10 },
        });
        return 42;
      }),
      42,
    );
    const primary = new Error('Application rejection');
    await assert.rejects(
      app.sql.transaction('main', async (tx) => {
        calls++;
        await tx.execute({ text: `INSERT INTO ${table} VALUES (2,20)` });
        throw primary;
      }),
      (error) => error === primary,
    );
    await assert.rejects(
      app.sql.execute('main', { text: `INSERT INTO ${table} VALUES (1,99)` }),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_DATABASE_CONSTRAINT' &&
        error.details?.errno === 1062,
    );
    assert.equal(calls, 2);
    assert.deepEqual(
      (await app.sql.query('main', { text: `SELECT * FROM ${table} ORDER BY id` })).rows,
      [{ id: '1', value: 10 }],
    );
  } finally {
    await close();
  }
});

test('EK-CORE-002 live MySQL pins concurrent callback statements and isolates named pools and applications', async () => {
  const plugin = mysqlPlugin();
  const first = await started(endpoint, 2, plugin, true);
  const second = await started(endpoint, 2, plugin);
  let stale: SqlTransaction | undefined;
  try {
    assert.notEqual(first.sql.native('main'), first.sql.native('secondary'));
    assert.notEqual(first.sql.native('main'), second.sql.native('main'));
    await first.sql.transaction('main', async (tx) => {
      stale = tx;
      const results = await Promise.all(
        Array.from({ length: 8 }, () => tx.query({ text: 'SELECT CONNECTION_ID() AS id' })),
      );
      assert.equal(new Set(results.map((result) => result.rows[0]?.id)).size, 1);
      await assert.rejects(
        first.sql.query('main', { text: 'SELECT 1' }),
        code('EK_DATABASE_TRANSACTION'),
      );
      await assert.rejects(
        first.sql.transaction('main', async () => 1),
        code('EK_DATABASE_TRANSACTION'),
      );
    });
    await assert.rejects(stale!.execute({ text: 'SELECT 1' }), code('EK_DATABASE_TRANSACTION'));
    await first.stop();
    assert.equal(await second.sql.ping('main'), true);
  } finally {
    await first.stop();
    await second.stop();
  }
});

test('EK-DB-001 live queued MySQL work captures mutable binds and follows actual session string modes', async () => {
  const app = await started();
  try {
    await app.sql.transaction('main', async (tx) => {
      const bytes = new Uint8Array([1, 2]);
      const date = new Date('2026-10-25T01:02:03.000Z');
      const changed = tx.execute({
        text: "SET SESSION sql_mode='ANSI_QUOTES,NO_BACKSLASH_ESCAPES'",
      });
      const read = tx.query({
        text: "SELECT 'a\\' AS literal, :bytes AS bytes, :date AS stamp",
        bindings: { bytes, date },
      });
      bytes[0] = 9;
      date.setUTCFullYear(2000);
      await changed;
      const row = (await read).rows[0]!;
      assert.equal(row.literal, 'a\\');
      assert.deepEqual(row.bytes, Buffer.from([1, 2]));
      assert.equal(String(row.stamp).slice(0, 19), '2026-10-25 01:02:03');
    });
  } finally {
    await app.stop();
  }
});

test('EK-CORE-001 live MySQL cancels abandoned pool waits and bounds real statement execution without replay', async () => {
  const app = await started(endpoint, 1);
  try {
    const native = app.sql.native('main') as Pool;
    const held = await borrowed(native);
    const before = app.sql.stats('main').operations;
    try {
      await assert.rejects(
        app.sql.query('main', { text: 'SELECT 99' }, { timeoutMs: 15 }),
        code('EK_DATABASE_POOL_TIMEOUT'),
      );
      const controller = new AbortController();
      const waiting = app.sql.query('main', { text: 'SELECT 98' }, { signal: controller.signal });
      await pause(5);
      controller.abort();
      await assert.rejects(waiting, code('EK_ABORTED'));
      assert.equal(app.sql.stats('main').operations, before);
    } finally {
      held.release();
    }
    await eventually(() => app.sql.stats('main').pendingAcquires === 0);
    const previous = await app.sql.queryOne('main', { text: 'SELECT CONNECTION_ID() AS id' });
    await assert.rejects(
      app.sql.query('main', { text: 'SELECT SLEEP(1)' }, { timeoutMs: 20 }),
      code('EK_TIMEOUT'),
    );
    const next = await app.sql.queryOne('main', { text: 'SELECT CONNECTION_ID() AS id' });
    assert.notEqual(previous?.id, next?.id);
    assert.equal(await app.sql.ping('main'), true);
  } finally {
    await app.stop();
  }
});

test('EK-SEC-001 live MySQL rejects wrong DNS identity, untrusted CA and invalid credentials', async () => {
  await assert.rejects(started(wrongSan), (error) =>
    nativeCode(
      error,
      ['HANDSHAKE_SSL_ERROR'],
      (native) =>
        'host' in native &&
        native.host === 'localhost' &&
        'reason' in native &&
        String(native.reason).includes('wrong.invalid'),
    ),
  );
  const untrusted = new URL(endpoint!);
  untrusted.searchParams.delete('sslca');
  await assert.rejects(started(untrusted.href), (error) =>
    nativeCode(
      error,
      ['HANDSHAKE_SSL_ERROR'],
      (native) =>
        native instanceof Error &&
        /self.signed|unable to verify|unable to get.*issuer/i.test(native.message),
    ),
  );
  const unauthorized = new URL(endpoint!);
  unauthorized.password = 'incorrect-private-test-password';
  await assert.rejects(started(unauthorized.href), (error) =>
    nativeCode(error, ['ER_ACCESS_DENIED_ERROR']),
  );
});

test('EK-DB-001 live MySQL deadlocks map actual errno 1213 without retrying either callback', async () => {
  const { app, table, close } = await fixture();
  try {
    await app.sql.execute('main', { text: `INSERT INTO ${table} VALUES (1,0),(2,0)` });
    let ready!: () => void;
    let arrivals = 0;
    const barrier = new Promise<void>((resolve) => {
      ready = resolve;
    });
    const calls = [0, 0];
    const results = await Promise.allSettled(
      [0, 1].map((index) =>
        app.sql.transaction(
          'main',
          async (tx) => {
            calls[index] = calls[index]! + 1;
            await tx.execute({
              text: `UPDATE ${table} SET value=value+1 WHERE id=:id`,
              bindings: { id: index + 1 },
            });
            if (++arrivals === 2) ready();
            await barrier;
            await tx.execute({
              text: `UPDATE ${table} SET value=value+1 WHERE id=:id`,
              bindings: { id: 2 - index },
            });
          },
          { timeoutMs: 5000 },
        ),
      ),
    );
    assert.deepEqual(calls, [1, 1]);
    assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
    const failure = results.find((result) => result.status === 'rejected');
    assert.ok(failure?.status === 'rejected');
    assert.ok(failure.reason instanceof KitError);
    assert.equal(failure.reason.code, 'EK_DATABASE_CONFLICT');
    assert.equal(failure.reason.details?.errno, 1213);
    assert.deepEqual(
      (await app.sql.query('main', { text: `SELECT value FROM ${table} ORDER BY id` })).rows,
      [{ value: 1 }, { value: 1 }],
    );
  } finally {
    await close();
  }
});

test('EK-DB-001 live MySQL reports DDL implicit commit and preserves the already committed effects honestly', async () => {
  const { app, table, close } = await fixture();
  const ddl = table + '_ddl';
  try {
    await assert.rejects(
      app.sql.transaction('main', async (tx) => {
        await tx.execute({ text: `INSERT INTO ${table} VALUES (1,10)` });
        await tx.execute({ text: `CREATE TABLE ${ddl} (id INT)` });
      }),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_DATABASE_TRANSACTION' &&
        error.details?.outcome === 'implicitly_committed' &&
        !error.retryable,
    );
    assert.deepEqual((await app.sql.query('main', { text: `SELECT value FROM ${table}` })).rows, [
      { value: 10 },
    ]);
    assert.equal((await app.sql.query('main', { text: `SELECT * FROM ${ddl}` })).rowCount, 0);
  } finally {
    try {
      await app.sql.execute('main', { text: `DROP TABLE IF EXISTS ${ddl}` });
    } finally {
      await close();
    }
  }
});

test('EK-DB-001 real MySQL COMMIT effects survive a lost acknowledgment and the callback is not replayed', async (context) => {
  const { app, table, close } = await fixture();
  const client = await borrowed(app.sql.native('main') as Pool);
  client.release();
  const query = client.query;
  let committed = 0,
    calls = 0;
  context.mock.method(client, 'query', function (this: PoolConnection, ...args: unknown[]) {
    if (args[0] === 'COMMIT') {
      const callback = args[args.length - 1];
      assert.equal(typeof callback, 'function');
      args[args.length - 1] = (error: unknown, result: unknown) => {
        if (error) Reflect.apply(callback as (...args: unknown[]) => void, undefined, [error]);
        else {
          committed++;
          Reflect.apply(callback as (...args: unknown[]) => void, undefined, [
            Object.assign(new Error('Commit acknowledgment lost'), { code: 'ECONNRESET' }),
            result,
          ]);
        }
      };
    }
    return Reflect.apply(query, this, args);
  } as typeof client.query);
  try {
    await assert.rejects(
      app.sql.transaction('main', async (tx) => {
        calls++;
        await tx.execute({ text: `INSERT INTO ${table} VALUES (1,10)` });
      }),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_DATABASE_TRANSACTION' &&
        error.details?.outcome === 'unknown' &&
        !error.retryable,
    );
    assert.equal(committed, 1);
    assert.equal(calls, 1);
    assert.deepEqual((await app.sql.query('main', { text: `SELECT value FROM ${table}` })).rows, [
      { value: 10 },
    ]);
  } finally {
    context.mock.restoreAll();
    await close();
  }
});

test('EK-DB-001 portable MySQL reset clears native prepared caches and previous session settings', async () => {
  const app = await started(endpoint, 1);
  try {
    const pool = app.sql.native('main') as Pool;
    const client = await pool.promise().getConnection();
    try {
      await client.execute('SELECT ? AS value', [1]);
      await client.query("SET SESSION sql_mode='ANSI_QUOTES', time_zone='+05:00'");
    } finally {
      client.release();
    }
    const settings = await app.sql.queryOne('main', {
      text: 'SELECT @@session.sql_mode AS mode, @@session.time_zone AS zone',
    });
    assert.equal(settings?.mode, 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION');
    assert.equal(settings?.zone, '+00:00');
    const next = await pool.promise().getConnection();
    try {
      const [rows] = await next.execute('SELECT ? AS value', [2]);
      assert.deepEqual(rows, [{ value: 2 }]);
    } finally {
      next.release();
    }
  } finally {
    await app.stop();
  }
});
