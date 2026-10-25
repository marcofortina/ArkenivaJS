import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { MongoClient, ClientSession, BSON } from 'mongodb';
import type { Plugin } from '@arkenivajs/core';
import { createApplication, KitError } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';
import { mongoConfiguration } from '../../dist/config.js';

const service = { name: 'mongodb-public-contract', version: '1.0.0', environment: 'test' as const };
async function fixture(context: TestContext, plugin: Plugin = mongodbPlugin()) {
  assert.equal(
    process.env.ARKENIVA_MONGODB_DISPOSABLE,
    '1',
    'Only a dedicated disposable MongoDB fixture is permitted',
  );
  assert.ok(process.env.ARKENIVA_MONGODB_URL, 'A verified authenticated MongoDB URI is required');
  const configuration = mongoConfiguration(
    { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_URL' },
    'test',
  );
  const app = await createApplication({
    service,
    plugins: [plugin],
    databases: { documents: { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_URL' } },
  });
  const names: string[] = [];
  context.after(async () => {
    try {
      if (names.length) {
        const cleanup = new MongoClient(configuration.url, configuration.native);
        try {
          await cleanup.connect();
          for (const name of names)
            await cleanup
              .db()
              .collection(configuration.prefix + name)
              .drop();
        } finally {
          await cleanup.close();
        }
      }
    } finally {
      await app.stop();
    }
  });
  await app.start();
  return {
    app,
    mongo: app.mongo!,
    native: app.mongo!.native() as MongoClient,
    configuration,
    collection() {
      const name = 'public_' + randomBytes(12).toString('hex');
      names.push(name);
      return name;
    },
  };
}

test('Real public MongoDB preserves native BSON values and opaque custom IDs and reports actual modification/deletion counts', async (context) => {
  const f = await fixture(context),
    name = f.collection();
  assert.ok(f.native instanceof MongoClient);
  assert.equal(await f.mongo.findOne(name, {}), null);
  const document = {
    _id: 'caller-string-id',
    amount: BSON.Decimal128.fromString('1234567890.123456789'),
    exact: BSON.Long.fromString('9007199254740993'),
    bytes: new BSON.Binary(Buffer.from([0, 255])),
    date: new Date('2026-10-25T00:00:00Z'),
    value: 42,
  };
  const writing = f.mongo.insertOne(name, document);
  document.bytes.buffer[0] = 99;
  const id = await writing;
  assert.equal(BSON.EJSON.parse(id, { relaxed: false }), 'caller-string-id');
  const row = await f.mongo.findOne<typeof document>(name, { _id: 'caller-string-id' });
  assert.ok(row?.amount instanceof BSON.Decimal128);
  assert.equal(row.amount.toString(), '1234567890.123456789');
  assert.ok(row.exact instanceof BSON.Long);
  assert.equal(row.exact.toString(), '9007199254740993');
  assert.ok(row.bytes instanceof BSON.Binary);
  assert.deepEqual(Buffer.from(row.bytes.buffer), Buffer.from([0, 255]));
  assert.ok(row.date instanceof Date);
  assert.equal(row.date.toISOString(), '2026-10-25T00:00:00.000Z');
  assert.equal(
    await f.mongo.updateOne(name, { _id: 'caller-string-id' }, { $set: { value: 42 } }),
    0,
  );
  assert.equal(
    await f.mongo.updateOne(name, { _id: 'caller-string-id' }, { $set: { value: 43 } }),
    1,
  );
  assert.equal(await f.mongo.deleteOne(name, { _id: 'caller-string-id' }), 1);
  assert.equal(await f.mongo.deleteOne(name, { _id: 'caller-string-id' }), 0);
  await f.mongo.insertOne(name, { _id: 'keep-collection' });
  assert.throws(() => f.app.sql, { code: 'EK_UNSUPPORTED_CAPABILITY' });
});

test('Real public MongoDB bounds findMany, preserves supplied aggregation and maps unique index failure', async (context) => {
  const f = await fixture(context),
    name = f.collection(),
    collection = f.native.db().collection(f.configuration.prefix + name);
  await collection.createIndex({ key: 1 }, { unique: true });
  await collection.insertMany(
    Array.from({ length: 105 }, (_, index) => ({ key: index, amount: index })),
  );
  assert.equal((await f.mongo.findMany(name, {})).length, 100);
  assert.equal((await f.mongo.findMany(name, {}, { limit: 3 })).length, 3);
  await assert.rejects(f.mongo.findMany(name, {}, { limit: 1001 }), { code: 'EK_CONFIG_INVALID' });
  const pipeline = [{ $match: { key: { $gte: 100 } } }, { $limit: 2 }, { $project: { key: 1 } }],
    before = BSON.EJSON.stringify(pipeline, { relaxed: false });
  assert.equal((await f.mongo.aggregate(name, pipeline)).length, 2);
  assert.equal(BSON.EJSON.stringify(pipeline, { relaxed: false }), before);
  await assert.rejects(f.mongo.aggregate(name, [{ $match: {} }]), { code: 'EK_CONFIG_INVALID' });
  await assert.rejects(f.mongo.insertOne(name, { key: 1 }), { code: 'EK_DATABASE_CONSTRAINT' });
});

test('Real public MongoDB executes one callback with an actual native session and verifies commit/rollback on its replica set', async (context) => {
  const f = await fixture(context),
    name = f.collection(),
    collection = f.native.db().collection(f.configuration.prefix + name);
  await collection.insertOne({ marker: 'seed' });
  let calls = 0,
    committed: ClientSession | undefined;
  const answer = await f.mongo.withTransaction(async (value) => {
    assert.ok(value instanceof ClientSession);
    committed = value;
    calls++;
    await collection.insertOne({ marker: 'committed' }, { session: value });
    return 42;
  });
  assert.equal(answer, 42);
  assert.equal(calls, 1);
  assert.equal(committed?.hasEnded, true);
  assert.ok(await f.mongo.findOne(name, { marker: 'committed' }));
  const rejected = new KitError({ code: 'EK_INTERNAL', message: 'The transaction body rejected' });
  let rolled: ClientSession | undefined;
  await assert.rejects(
    f.mongo.withTransaction(async (value) => {
      assert.ok(value instanceof ClientSession);
      rolled = value;
      calls++;
      await collection.insertOne({ marker: 'rolled-back' }, { session: value });
      throw rejected;
    }),
    (cause: unknown) => cause instanceof KitError && cause.details.outcome === 'rolled_back',
  );
  assert.equal(calls, 2);
  assert.equal(rolled?.hasEnded, true);
  assert.equal(await f.mongo.findOne(name, { marker: 'rolled-back' }), null);
});

test('Reusable MongoDB plugin factories keep native clients and lifecycle isolated between applications', async (context) => {
  const plugin = mongodbPlugin(),
    a = await fixture(context, plugin),
    b = await fixture(context, plugin),
    name = a.collection();
  assert.notEqual(a.native, b.native);
  assert.notEqual(a.mongo, b.mongo);
  await a.mongo.insertOne(name, { marker: 'owned' });
  await a.app.stop();
  await assert.rejects(a.mongo.findOne(name, {}), { code: 'EK_RESOURCE_CLOSED' });
  assert.ok(await b.mongo.findOne(name, { marker: 'owned' }));
});

test('Real MongoDB rolls back a callback that settles after its public deadline without a late commit', async (context) => {
  const f = await fixture(context),
    name = f.collection(),
    collection = f.native.db().collection(f.configuration.prefix + name);
  await collection.insertOne({ marker: 'seed' });
  let release!: () => void,
    session: ClientSession | undefined,
    commits = 0;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  f.native.on('commandStarted', (event) => {
    if (event.commandName === 'commitTransaction') commits++;
  });
  try {
    await assert.rejects(
      f.mongo.withTransaction(
        async (value) => {
          assert.ok(value instanceof ClientSession);
          session = value;
          await collection.insertOne({ marker: 'late-callback' }, { session: value });
          await gate;
          return 42;
        },
        { timeoutMs: 250 },
      ),
      { code: 'EK_TIMEOUT' },
    );
    assert.equal(session?.hasEnded, false);
  } finally {
    release();
  }
  const deadline = performance.now() + 3000;
  while (!session?.hasEnded) {
    assert.ok(performance.now() < deadline, 'The expired transaction did not release its session');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(commits, 0);
  assert.equal(await f.mongo.findOne(name, { marker: 'late-callback' }), null);
});

test('Real MongoDB preserves unknown partial aggregation effects when a native merge encounters a unique constraint', async (context) => {
  const f = await fixture(context),
    source = f.collection(),
    target = f.collection(),
    nativeSource = f.native
      .db()
      .collection<{ _id: string; key: string }>(f.configuration.prefix + source),
    nativeTarget = f.native.db().collection(f.configuration.prefix + target);
  await nativeSource.insertMany([
    { _id: 'first', key: 'same' },
    { _id: 'second', key: 'same' },
  ]);
  await nativeTarget.createIndex({ key: 1 }, { unique: true });
  await assert.rejects(
    f.mongo.aggregate(source, [
      { $sort: { _id: 1 } },
      {
        $merge: {
          into: nativeTarget.collectionName,
          on: '_id',
          whenMatched: 'fail',
          whenNotMatched: 'insert',
        },
      },
    ]),
    (cause: unknown) => {
      assert.ok(cause instanceof KitError);
      assert.equal(
        cause.code,
        'EK_DATABASE_CONSTRAINT',
        'Native aggregation code: ' + String((cause.cause as { code?: number })?.code),
      );
      assert.equal(cause.details.outcome, 'unknown');
      assert.equal(cause.retryable, false);
      return true;
    },
  );
  assert.equal(await nativeTarget.countDocuments(), 1);
});

test('Real MongoDB application drain closes native change streams and their pending cursor work', async (context) => {
  const f = await fixture(context),
    name = f.collection(),
    collection = f.native.db().collection(f.configuration.prefix + name);
  await collection.insertOne({ marker: 'seed' });
  const stream = collection.watch([], { maxAwaitTimeMS: 1000 });
  try {
    await stream.tryNext();
    await f.app.stop();
    assert.equal(stream.closed, true);
    await assert.rejects(stream.next());
  } finally {
    await stream.close();
  }
});
