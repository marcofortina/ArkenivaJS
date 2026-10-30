// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createSecureContext } from 'node:tls';
import { MongoClient, ClientSession, BSON } from 'mongodb';

export function mongodbConnection(fixture) {
  try {
    const url = new URL(fixture.url),
      parameters = new Map();
    assert.equal(url.protocol, 'mongodb:');
    assert.equal(url.hostname, 'localhost');
    assert.ok(url.port && url.username && url.password && url.pathname.length > 1 && !url.hash);
    for (const [key, value] of url.searchParams) {
      const name = key.toLowerCase();
      assert.ok(
        ['tls', 'tlscafile', 'authsource', 'directconnection', 'replicaset', 'prefix'].includes(
          name,
        ),
      );
      assert.equal(parameters.has(name), false);
      parameters.set(name, value);
    }
    assert.equal(parameters.get('tls'), 'true');
    assert.equal(parameters.get('directconnection'), 'true');
    assert.ok(parameters.get('tlscafile')?.startsWith('/'));
    const prefix = parameters.get('prefix') ?? '';
    assert.match(prefix, /^[A-Za-z0-9_-]{0,64}$/);
    assert.match(fixture.collection, /^comparison_[a-f0-9]{32}$/);
    const caFile = parameters.get('tlscafile');
    for (const key of [...url.searchParams.keys()])
      if (['tlscafile', 'prefix'].includes(key.toLowerCase())) url.searchParams.delete(key);
    return {
      url,
      caFile,
      prefix,
      database: decodeURIComponent(url.pathname.slice(1)),
      physical: prefix + fixture.collection,
    };
  } catch {
    throw new Error(
      'The owned MongoDB comparison requires verified localhost TLS, scoped credentials and a random collection',
    );
  }
}

export async function connectMongo(fixture) {
  const config = mongodbConnection(fixture);
  const client = new MongoClient(config.url.toString(), {
    tls: true,
    secureContext: createSecureContext({
      ca: await readFile(config.caFile),
      minVersion: 'TLSv1.2',
    }),
    rejectUnauthorized: true,
    authMechanism: 'SCRAM-SHA-256',
    minPoolSize: 0,
    maxPoolSize: 8,
    maxConnecting: 2,
    waitQueueTimeoutMS: 5000,
    connectTimeoutMS: 5000,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 0,
    retryReads: false,
    retryWrites: false,
    maxAdaptiveRetries: 0,
    enableOverloadRetargeting: false,
    monitorCommands: true,
    promoteLongs: false,
    mongodbLogComponentSeverities: {
      default: 'off',
      command: 'off',
      topology: 'off',
      serverSelection: 'off',
      connection: 'off',
      client: 'off',
    },
  });
  try {
    await client.connect();
    await client.db(config.database).command({ ping: 1 });
    return client;
  } catch {
    await client.close();
    throw new Error('The owned native MongoDB comparison connection failed');
  }
}

/** Native driver operations retain BSON and transaction semantics for the declared bounded corpus. */
export async function nativeMongo(fixture) {
  const client = await connectMongo(fixture);
  const collection = (name) => {
    const config = mongoCollectionConfiguration(fixture, name);
    return client.db(config.database).collection(config.physical);
  };
  return {
    native: () => client,
    findOne: (name, filter) =>
      collection(name).findOne(filter, {
        promoteValues: false,
        promoteLongs: false,
        bsonRegExp: true,
      }),
    async findMany(name, filter, options) {
      const cursor = collection(name)
        .find(filter, { promoteValues: false, promoteLongs: false, bsonRegExp: true })
        .limit(options.limit);
      try {
        return await cursor.toArray();
      } finally {
        await cursor.close();
      }
    },
    async insertOne(name, document) {
      const result = await collection(name).insertOne(document);
      return BSON.EJSON.stringify(result.insertedId, { relaxed: false });
    },
    async updateOne(name, filter, update) {
      return (await collection(name).updateOne(filter, update)).modifiedCount;
    },
    async deleteOne(name, filter) {
      return (await collection(name).deleteOne(filter)).deletedCount;
    },
    async aggregate(name, pipeline) {
      const cursor = collection(name).aggregate(pipeline, {
        promoteValues: false,
        promoteLongs: false,
        bsonRegExp: true,
      });
      try {
        return await cursor.toArray();
      } finally {
        await cursor.close();
      }
    },
    async withTransaction(handler) {
      const session = client.startSession();
      try {
        session.startTransaction();
        const result = await handler(session);
        await session.commitTransaction();
        return result;
      } catch (cause) {
        if (session.inTransaction()) await session.abortTransaction();
        throw cause;
      } finally {
        await session.endSession();
      }
    },
    close: () => client.close(),
  };
}

/** Only the two explicitly declared comparison namespaces may reach the baseline driver. */
export function mongoCollectionConfiguration(fixture, name) {
  assert.ok(
    name === fixture.collection ||
      (fixture.readCollection !== undefined && name === fixture.readCollection),
  );
  return mongodbConnection({ ...fixture, collection: name });
}

export async function dropOwnedMongo(client, fixture) {
  const config = mongodbConnection(fixture);
  try {
    await client.db(config.database).collection(config.physical).drop();
  } catch (cause) {
    if (cause.code !== 26) throw cause;
  }
}

export async function verifyMongo(service, fixture) {
  const config = mongodbConnection(fixture),
    observer = await connectMongo(fixture);
  const database = observer.db(config.database),
    physical = database.collection(config.physical);
  let owned = false;
  try {
    assert.ok(service.native() instanceof MongoClient);
    assert.equal(
      (await database.listCollections({ name: config.physical }, { nameOnly: true }).toArray())
        .length,
      0,
    );
    owned = true;
    const name = fixture.collection,
      filter = { tenant: fixture.marker };
    assert.equal(await service.findOne(name, filter), null);
    const document = {
      _id: 'first',
      ...filter,
      count: 7,
      exact: BSON.Long.fromString('9007199254740993'),
      amount: BSON.Decimal128.fromString('1234567890.123456789'),
      payload: new BSON.Binary(Buffer.from([0, 255, 128, 7])),
      date: new Date('2026-10-25T00:00:00.000Z'),
    };
    assert.equal(
      BSON.EJSON.parse(await service.insertOne(name, document), { relaxed: false }),
      'first',
    );
    await service.insertOne(name, { _id: 'second', ...filter, count: 3 });
    const row = await service.findOne(name, { ...filter, _id: 'first' });
    assert.ok(row.exact instanceof BSON.Long);
    assert.equal(row.exact.toString(), '9007199254740993');
    assert.ok(row.amount instanceof BSON.Decimal128);
    assert.equal(row.amount.toString(), '1234567890.123456789');
    assert.ok(row.payload instanceof BSON.Binary);
    assert.deepEqual(Buffer.from(row.payload.buffer), Buffer.from([0, 255, 128, 7]));
    assert.ok(row.date instanceof Date);
    assert.equal(row.date.toISOString(), document.date.toISOString());
    const rows = await service.findMany(name, filter, { limit: 2 });
    assert.deepEqual(rows.map((item) => item._id).sort(), ['first', 'second']);
    assert.equal(
      await service.updateOne(name, { ...filter, _id: 'first' }, { $set: { count: 7 } }),
      0,
    );
    assert.equal(
      await service.updateOne(name, { ...filter, _id: 'first' }, { $inc: { count: 2 } }),
      1,
    );
    assert.equal((await physical.findOne({ _id: 'first' })).count, 9);
    assert.deepEqual(
      await service.aggregate(name, [
        { $match: filter },
        { $group: { _id: '$tenant', total: { $sum: '$count' } } },
        { $limit: 1 },
      ]),
      [{ _id: fixture.marker, total: new BSON.Int32(12) }],
    );
    const nativeCollection = service.native().db(config.database).collection(config.physical);
    let commitCalls = 0,
      abortCalls = 0,
      committed,
      aborted;
    assert.equal(
      await service.withTransaction(async (session) => {
        assert.ok(session instanceof ClientSession);
        committed = session;
        commitCalls++;
        await nativeCollection.insertOne({ _id: 'committed', ...filter }, { session });
        return 42;
      }),
      42,
    );
    assert.equal(commitCalls, 1);
    assert.equal(committed.hasEnded, true);
    assert.ok(await physical.findOne({ _id: 'committed' }));
    await assert.rejects(
      service.withTransaction(async (session) => {
        assert.ok(session instanceof ClientSession);
        aborted = session;
        abortCalls++;
        await nativeCollection.insertOne({ _id: 'aborted', ...filter }, { session });
        throw new Error('The owned MongoDB transaction deliberately aborted');
      }),
    );
    assert.equal(abortCalls, 1);
    assert.equal(aborted.hasEnded, true);
    assert.equal(await physical.findOne({ _id: 'aborted' }), null);
    assert.equal(await service.deleteOne(name, { ...filter, _id: 'first' }), 1);
    assert.equal(await service.deleteOne(name, { ...filter, _id: 'first' }), 0);
    assert.equal(await physical.countDocuments(filter), 2);
    return {
      actualCrudAndCountsVerified: true,
      exactNativeBsonPreserved: true,
      opaqueCustomIdVerified: true,
      unchangedAggregationVerified: true,
      commitAndRollbackVerified: true,
      callbackInvocations: [commitCalls, abortCalls],
      nativeSessionsEnded: true,
    };
  } finally {
    try {
      if (owned) await dropOwnedMongo(observer, fixture);
    } finally {
      await observer.close();
    }
  }
}

const readObservations = new WeakMap();
const readOptions = { promoteValues: false, promoteLongs: false, bsonRegExp: true };

export function mongoReadConfiguration(fixture) {
  assert.notEqual(fixture.readCollection, fixture.collection);
  assert.match(fixture.readId, /^read_[a-f0-9]{32}$/);
  return mongodbConnection({ ...fixture, collection: fixture.readCollection });
}

/** A finite BSON document makes decoding/type fidelity part of the observed operation. */
export function mongoReadDocument(fixture) {
  assert.match(fixture.readId, /^read_[a-f0-9]{32}$/);
  assert.equal(typeof fixture.marker, 'string');
  assert.ok(fixture.marker.length > 0 && fixture.marker.length <= 128);
  return {
    _id: fixture.readId,
    tenant: fixture.marker,
    count: new BSON.Int32(7),
    exact: BSON.Long.fromString('9007199254740993'),
    amount: BSON.Decimal128.fromString('123.25'),
    payload: new BSON.Binary(Buffer.from([0, 255, 128, 7])),
    date: new Date('2026-10-25T00:00:00.000Z'),
  };
}

export function checkMongoReadDocument(value, fixture) {
  assert.ok(value && typeof value === 'object');
  assert.ok(value.count instanceof BSON.Int32);
  assert.ok(value.exact instanceof BSON.Long);
  assert.ok(value.amount instanceof BSON.Decimal128);
  assert.ok(value.payload instanceof BSON.Binary);
  assert.ok(value.date instanceof Date);
  assert.equal(
    BSON.EJSON.stringify(value, { relaxed: false }),
    BSON.EJSON.stringify(mongoReadDocument(fixture), { relaxed: false }),
  );
  const bytes = BSON.serialize(value).length;
  assert.ok(bytes > 0 && bytes <= 4096);
  return bytes;
}

async function inspectMongoRead(collection, fixture, phase) {
  const documents = await collection.countDocuments({}),
    value = await collection.findOne({ _id: fixture.readId }, readOptions);
  assert.equal(documents, 1);
  return { phase, documents, bsonDocumentBytes: checkMongoReadDocument(value, fixture) };
}

/** Native seed/readback uses a separate client and remains outside the measured callback. */
export async function prepareMongoRead(service, fixture) {
  const config = mongoReadConfiguration(fixture),
    observer = await connectMongo(fixture);
  let owned = false;
  try {
    const database = observer.db(config.database),
      collection = database.collection(config.physical);
    assert.equal(
      (await database.listCollections({ name: config.physical }, { nameOnly: true }).toArray())
        .length,
      0,
    );
    owned = true;
    const inserted = await collection.insertOne(mongoReadDocument(fixture));
    assert.equal(inserted.acknowledged, true);
    assert.equal(inserted.insertedId, fixture.readId);
    const before = await inspectMongoRead(collection, fixture, 'before');
    assert.equal(readObservations.has(service), false);
    readObservations.set(service, {
      before,
      returnedBsonBytes: [],
      started: 0,
      succeeded: 0,
      failed: 0,
      getMore: 0,
      pending: new Set(),
      detach: undefined,
    });
  } catch (error) {
    if (owned) await dropOwnedMongo(observer, { ...fixture, collection: fixture.readCollection });
    throw error;
  } finally {
    await observer.close();
  }
}

/** Count real commands without retaining their documents, credentials, request IDs or namespaces. */
export function mongoReadWorkload(service, fixture) {
  const state = readObservations.get(service),
    client = service.native(),
    config = mongoReadConfiguration(fixture);
  assert.ok(state && client instanceof MongoClient && state.detach === undefined);
  const started = (event) => {
    if (event.databaseName !== config.database) return;
    if (event.commandName === 'getMore' && event.command.collection === config.physical)
      state.getMore++;
    if (event.commandName !== 'find' || event.command.find !== config.physical) return;
    assert.ok(state.pending.size < 1 && !state.pending.has(event.requestId));
    state.pending.add(event.requestId);
    state.started++;
  };
  const succeeded = (event) => {
    if (!state.pending.delete(event.requestId)) return;
    assert.equal(event.commandName, 'find');
    state.succeeded++;
  };
  const failed = (event) => {
    if (!state.pending.delete(event.requestId)) return;
    state.failed++;
  };
  client.on('commandStarted', started);
  client.on('commandSucceeded', succeeded);
  client.on('commandFailed', failed);
  state.detach = () => {
    client.off('commandStarted', started);
    client.off('commandSucceeded', succeeded);
    client.off('commandFailed', failed);
  };
  return {
    'find-one-owned-bson-document': async () => {
      assert.ok(state.returnedBsonBytes.length < 128, 'MongoDB callback capacity is exceeded');
      const value = await service.findOne(fixture.readCollection, {
        _id: fixture.readId,
        tenant: fixture.marker,
      });
      state.returnedBsonBytes.push(checkMongoReadDocument(value, fixture));
      return 1;
    },
  };
}

export function summarizeMongoRead(state, record) {
  assert.equal(record.operation, 'find-one-owned-bson-document');
  assert.equal(record.sampleCount, 100);
  assert.equal(record.warmupIterations, 20);
  const actualCallbacks = state.returnedBsonBytes.length;
  assert.equal(actualCallbacks, record.sampleCount + record.warmupIterations);
  assert.equal(record.rawLatency.values.length, record.sampleCount);
  assert.equal(state.started, actualCallbacks);
  assert.equal(state.succeeded, actualCallbacks);
  assert.equal(state.failed, 0);
  assert.equal(state.getMore, 0);
  assert.equal(state.pending.size, 0);
  assert.ok(state.returnedBsonBytes.every((value) => Number.isSafeInteger(value) && value > 0));
  return {
    actualCallbacks,
    measuredCallbacks: record.sampleCount,
    warmupCallbacks: record.warmupIterations,
    findCommandsStarted: state.started,
    findCommandsSucceeded: state.succeeded,
    findCommandsFailed: state.failed,
    getMoreCommandsStarted: state.getMore,
    outstandingCommands: state.pending.size,
    observedBsonResultBytes: state.returnedBsonBytes.reduce((sum, value) => sum + value, 0),
    wireBytes: null,
  };
}

export async function completeMongoRead(service, { fixture, measure, records }) {
  if (!measure) return undefined;
  const state = readObservations.get(service);
  assert.ok(state);
  readObservations.delete(service);
  state.detach?.();
  assert.equal(records.length, 1);
  const actual = summarizeMongoRead(state, records[0]),
    config = mongoReadConfiguration(fixture),
    observer = await connectMongo(fixture);
  try {
    const database = observer.db(config.database),
      collection = database.collection(config.physical),
      after = await inspectMongoRead(collection, fixture, 'after');
    assert.equal(after.bsonDocumentBytes, state.before.bsonDocumentBytes);
    await dropOwnedMongo(observer, { ...fixture, collection: fixture.readCollection });
    const remaining = (
      await database.listCollections({ name: config.physical }, { nameOnly: true }).toArray()
    ).length;
    assert.equal(remaining, 0);
    return {
      ...actual,
      independentReadbacks: [state.before, after],
      ownedCollectionsRemaining: remaining,
      externalServerResourcesIncluded: false,
    };
  } finally {
    await observer.close();
  }
}
