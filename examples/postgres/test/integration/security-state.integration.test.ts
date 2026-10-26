// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { KitError } from '@arkenivajs/core';
import type { SecurityAtomicMutation } from '../../dist/security-state-store.js';
import { securityStateFixture } from './security-state-fixture.js';

const owner = () => randomBytes(32).toString('hex'),
  ns = 'credential-state';
function worker(
  t: TestContext,
  schema: string,
  operation: 'claim' | 'cas' | 'batch' | 'bump',
  args: readonly unknown[],
) {
  const script = `
    import {createApplication,KitError} from '@arkenivajs/core';
    import {postgresPlugin} from '@arkenivajs/database-postgres';
    import {createInterface} from 'node:readline';
    import {createPostgresSecurityStateStore} from './dist/security-state-store.js';
    const app=await createApplication({service:{name:'security-state-worker',version:'1.0.0',environment:'test'},plugins:[postgresPlugin()],databases:{main:{driver:'postgresql',connectionStringEnv:'DATABASE_URL',poolMax:1}}});
    const lines=createInterface({input:process.stdin}),iterator=lines[Symbol.asyncIterator]();
    try{const frame=(await iterator.next()).value;if(typeof frame!=='string'||frame.length>1048576)throw new Error('Invalid fixture frame');const input=JSON.parse(frame);await app.start();const store=createPostgresSecurityStateStore(app.sql,'main',input.schema);const go=iterator.next();console.log(JSON.stringify({ready:true}));if((await go).value!=='go')throw new Error('Invalid fixture barrier');const method={claim:'claimOnce',cas:'compareAndSet',batch:'atomicBatch',bump:'bumpOwnerEpoch'}[input.operation];const result=await store[method](...input.args);console.log(JSON.stringify({result:typeof result==='object'?result.committed:result}));}
    catch(error){console.error(JSON.stringify(error instanceof KitError?error.toSafeJSON():{code:'EK_INTERNAL'}));process.exitCode=1;}finally{lines.close();process.stdin.destroy();await app.stop();}
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', script], {
    cwd: fileURLToPath(new URL('../../', import.meta.url)),
    env: process.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  t.after(() => {
    if (child.exitCode === null) child.kill('SIGTERM');
  });
  let answer: boolean | number | undefined,
    diagnostic = '';
  let resolveReady!: () => void, rejectReady!: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  void ready.catch(() => undefined);
  const lines = createInterface({ input: child.stdout });
  lines.on('line', (line) => {
    const value = JSON.parse(line) as { ready?: boolean; result?: boolean | number };
    if (value.ready === true) resolveReady();
    if (value.result !== undefined) answer = value.result;
  });
  child.stderr.on('data', (chunk) => {
    diagnostic = (diagnostic + String(chunk)).slice(-4096);
  });
  const result = new Promise<boolean | number>((resolve, reject) => {
    child.once('error', (error) => {
      rejectReady(error);
      reject(error);
    });
    child.once('close', (code) => {
      lines.close();
      if (code === 0 && answer !== undefined) resolve(answer);
      else {
        const error = new Error('Security state worker failed: ' + diagnostic);
        rejectReady(error);
        reject(error);
      }
    });
  });
  void result.catch(() => undefined);
  child.stdin.write(JSON.stringify({ schema, operation, args }) + '\n');
  return {
    ready,
    result,
    go() {
      child.stdin.end('go\n');
    },
  };
}

test(
  'Security state durable CAS versions, indexed owners and TTL cannot cross namespaces or silently truncate',
  { timeout: 30000 },
  async () => {
    const f = await securityStateFixture(),
      first = owner(),
      second = owner();
    try {
      const created = await f.store.compareAndSet(ns, 'one', null, { ownerKey: first, value: 1 });
      assert.equal(created.committed, true);
      assert.ok(created.version);
      const current = await f.peer.read(ns, 'one');
      assert.equal(current?.version, created.version);
      assert.equal(current?.value, 1);
      assert.ok(Object.isFrozen(current));
      assert.equal(
        (await f.peer.compareAndSet(ns, 'one', null, { ownerKey: first, value: 9 })).committed,
        false,
      );
      assert.equal(
        (await f.peer.compareAndSet(ns, 'one', randomUUID(), { ownerKey: first, value: 9 }))
          .committed,
        false,
      );
      assert.equal(
        (await f.peer.compareAndSet(ns, 'one', created.version!, { ownerKey: second, value: 9 }))
          .committed,
        false,
      );
      await f.store.compareAndSet(ns, 'two', null, { ownerKey: first, value: 2 });
      await f.store.compareAndSet(ns, 'foreign', null, { ownerKey: second, value: 3 });
      await f.store.compareAndSet('other-namespace', 'one', null, { ownerKey: first, value: 4 });
      assert.deepEqual(
        (await f.peer.listByOwner(ns, first, 2)).map((record) => record.id),
        ['one', 'two'],
      );
      await assert.rejects(f.peer.listByOwner(ns, first, 1));
      assert.equal((await f.peer.listByOwner(ns, second, 2)).length, 1);
      const expired = await f.store.compareAndSet(ns, 'expired', null, {
        ownerKey: first,
        expiresAt: new Date(Date.now() - 10000).toISOString(),
      });
      assert.equal(expired.committed, true);
      assert.equal(await f.peer.read(ns, 'expired'), null);
      assert.equal(
        (await f.peer.compareAndSet(ns, 'expired', expired.version!, { ownerKey: first }))
          .committed,
        false,
      );
      assert.equal(
        (await f.peer.compareAndSet(ns, 'expired', null, { ownerKey: first, value: 'fresh' }))
          .committed,
        true,
      );
      assert.equal((await f.peer.compareAndSet(ns, 'one', created.version!, null)).committed, true);
      assert.equal(await f.store.read(ns, 'one'), null);
      assert.equal((await f.peer.compareAndSet(ns, 'absent', null, null)).committed, true);
    } finally {
      await f.close();
    }
  },
);
test(
  'Security batch rolls back earlier writes and binds every row to its indexed owner',
  { timeout: 30000 },
  async () => {
    const f = await securityStateFixture(),
      subject = owner();
    try {
      const initial = await f.store.compareAndSet(ns, 'z-guard', null, {
        ownerKey: subject,
        value: 'original',
      });
      const attempted: SecurityAtomicMutation[] = [
        {
          namespace: ns,
          id: 'a-created',
          expectedVersion: null,
          ownerKey: subject,
          next: { value: 'must-roll-back' },
        },
        {
          namespace: ns,
          id: 'z-guard',
          expectedVersion: randomUUID(),
          ownerKey: subject,
          next: null,
        },
      ];
      assert.equal((await f.peer.atomicBatch(attempted)).committed, false);
      assert.equal(await f.store.read(ns, 'a-created'), null);
      assert.equal((await f.store.read(ns, 'z-guard'))?.version, initial.version);
      assert.equal(
        (
          await f.peer.atomicBatch([
            {
              namespace: ns,
              id: 'z-guard',
              expectedVersion: initial.version!,
              ownerKey: owner(),
              next: null,
            },
          ])
        ).committed,
        false,
      );
      const updated = await f.peer.atomicBatch([
        { ...attempted[1]!, expectedVersion: initial.version! },
        attempted[0]!,
      ]);
      assert.equal(updated.committed, true);
      assert.equal((await f.store.read(ns, 'a-created'))?.version, updated.version);
      assert.equal(await f.store.read(ns, 'z-guard'), null);
    } finally {
      await f.close();
    }
  },
);
test(
  'Security claims and CAS select exactly one winner across independent operating-system processes',
  { timeout: 30000 },
  async (t) => {
    const f = await securityStateFixture(),
      digest = owner(),
      subject = owner();
    try {
      for (const [operation, args] of [
        ['claim', [ns, digest, new Date(Date.now() + 60000).toISOString()]],
        ['cas', [ns, 'contended', null, { ownerKey: subject, value: true }]],
      ] as const) {
        const first = worker(t, f.schema, operation, args),
          second = worker(t, f.schema, operation, args);
        await Promise.all([first.ready, second.ready]);
        first.go();
        second.go();
        const outcomes = await Promise.all([first.result, second.result]);
        assert.equal(outcomes.filter(Boolean).length, 1);
      }
      assert.equal(
        await f.store.claimOnce(ns, owner(), new Date(Date.now() - 10000).toISOString()),
        false,
      );
    } finally {
      await f.close();
    }
  },
);
test(
  'Security competing all-or-nothing rotations do not publish a partial credential or deadlock reversed batches',
  { timeout: 30000 },
  async (t) => {
    const f = await securityStateFixture(),
      subject = owner();
    try {
      const a = await f.store.compareAndSet(ns, 'a', null, { ownerKey: subject, value: 0 }),
        b = await f.store.compareAndSet(ns, 'b', null, { ownerKey: subject, value: 0 });
      const mutations: SecurityAtomicMutation[] = [
        {
          namespace: ns,
          id: 'a',
          expectedVersion: a.version!,
          ownerKey: subject,
          next: { value: 1 },
        },
        {
          namespace: ns,
          id: 'b',
          expectedVersion: b.version!,
          ownerKey: subject,
          next: { value: 1 },
        },
      ];
      const first = worker(t, f.schema, 'batch', [mutations]),
        second = worker(t, f.schema, 'batch', [[...mutations].reverse()]);
      await Promise.all([first.ready, second.ready]);
      first.go();
      second.go();
      const results = await Promise.all([first.result, second.result]);
      assert.equal(results.filter(Boolean).length, 1);
      assert.equal((await f.store.read(ns, 'a'))?.value, 1);
      assert.equal((await f.store.read(ns, 'b'))?.value, 1);
      assert.equal((await f.store.read(ns, 'a'))?.version, (await f.store.read(ns, 'b'))?.version);
    } finally {
      await f.close();
    }
  },
);
test(
  'Security owner epochs increase across processes, isolate scope and reject unsafe numeric overflow',
  { timeout: 30000 },
  async (t) => {
    const f = await securityStateFixture(),
      subject = owner();
    try {
      assert.equal(await f.store.currentOwnerEpoch(ns, subject), 0);
      const first = worker(t, f.schema, 'bump', [ns, subject]),
        second = worker(t, f.schema, 'bump', [ns, subject]);
      await Promise.all([first.ready, second.ready]);
      first.go();
      second.go();
      const values = await Promise.all([first.result, second.result]);
      assert.deepEqual(values.sort(), [1, 2]);
      assert.equal(await f.peer.currentOwnerEpoch(ns, subject), 2);
      assert.equal(await f.peer.currentOwnerEpoch('other', subject), 0);
      assert.equal(await f.peer.currentOwnerEpoch(ns, owner()), 0);
      await f.app.sql.execute('main', {
        text: `UPDATE ${f.schema}.security_epochs SET epoch=9007199254740991 WHERE namespace=:namespace AND owner_key=:owner`,
        bindings: { namespace: ns, owner: subject },
      });
      await assert.rejects(f.store.bumpOwnerEpoch(ns, subject));
      assert.equal(await f.peer.currentOwnerEpoch(ns, subject), Number.MAX_SAFE_INTEGER);
    } finally {
      await f.close();
    }
  },
);
test(
  'Corrupt indexed security metadata and unavailable persistence never become successful state',
  { timeout: 30000 },
  async () => {
    const f = await securityStateFixture(),
      subject = owner();
    try {
      await f.store.compareAndSet(ns, 'record', null, { ownerKey: subject, value: true });
      await f.app.sql.execute('main', {
        text: `UPDATE ${f.schema}.security_records SET body=jsonb_set(body::jsonb,'{ownerKey}',to_jsonb(:foreign::text))::text WHERE namespace=:namespace AND id=:id`,
        bindings: { namespace: ns, id: 'record', foreign: owner() },
      });
      await assert.rejects(f.peer.read(ns, 'record'));
      await assert.rejects(f.peer.listByOwner(ns, subject, 10));
      await f.app.sql.execute('main', { text: `DROP TABLE ${f.schema}.security_claims` });
      await assert.rejects(
        f.store.claimOnce(ns, owner(), new Date(Date.now() + 60000).toISOString()),
        (error) => {
          assert.ok(error instanceof KitError);
          assert.equal(error.code, 'EK_DATABASE_UNAVAILABLE');
          assert.equal(error.cause, undefined);
          assert.equal(error.details.outcome, 'unknown');
          return true;
        },
      );
    } finally {
      await f.close();
    }
  },
);

test(
  'Security state preserves bounded nested JSON and uses its owner index under a selective real query',
  { timeout: 30000 },
  async () => {
    const f = await securityStateFixture(),
      subject = owner(),
      foreign = owner();
    try {
      const value = {
        ownerKey: subject,
        label: 'Unicode café 日本語',
        enabled: true,
        nullable: null,
        count: 42,
        maximumFinite: Number.MAX_VALUE,
        minimumPositive: Number.MIN_VALUE,
        nested: { values: [false, 0, 'value', null] },
      };
      const created = await f.store.compareAndSet(ns, 'nested', null, value),
        loaded = await f.peer.read(ns, 'nested');
      assert.deepEqual(JSON.parse(JSON.stringify(loaded)), { ...value, version: created.version });
      assert.ok(Object.isFrozen(loaded?.nested));
      await f.app.sql.execute('main', {
        text: `INSERT INTO ${f.schema}.security_records(namespace,id,owner_key,version,body) SELECT :namespace,'noise-'||entry,:owner,:version::uuid,jsonb_build_object('ownerKey',:owner::text,'value',entry)::text FROM generate_series(1,2000) AS entry`,
        bindings: { namespace: ns, owner: foreign, version: randomUUID() },
      });
      await f.app.sql.execute('main', { text: `ANALYZE ${f.schema}.security_records` });
      const plan = await f.app.sql.queryOne<{ 'QUERY PLAN': string }>('main', {
        text: `EXPLAIN(FORMAT JSON) SELECT id FROM ${f.schema}.security_records WHERE namespace=:namespace AND owner_key=:owner ORDER BY id LIMIT 2`,
        bindings: { namespace: ns, owner: subject },
      });
      assert.equal(typeof plan?.['QUERY PLAN'], 'string');
      assert.ok(plan!['QUERY PLAN'].includes('security_records_owner'));
      assert.deepEqual(
        (await f.store.listByOwner(ns, subject, 10)).map((value) => value.id),
        ['nested'],
      );
      const digest = owner(),
        expiresAt = new Date(Date.now() + 60000).toISOString();
      assert.equal(await f.store.claimOnce(ns, digest, expiresAt), true);
      assert.equal(await f.store.claimOnce(ns, digest, expiresAt), false);
      await f.app.sql.execute('main', {
        text: `UPDATE ${f.schema}.security_claims SET expires_at=clock_timestamp()-interval '1 second' WHERE namespace=:namespace AND digest=:digest`,
        bindings: { namespace: ns, digest },
      });
      assert.equal(await f.peer.claimOnce(ns, digest, expiresAt), true);
    } finally {
      await f.close();
    }
  },
);
