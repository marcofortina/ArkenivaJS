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
  const client = await connectMongo(fixture),
    config = mongodbConnection(fixture);
  const collection = (name) => {
    assert.equal(name, fixture.collection);
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
