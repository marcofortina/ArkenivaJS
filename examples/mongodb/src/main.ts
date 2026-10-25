// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { BSON, MongoClient, ClientSession } from 'mongodb';
import { ConnectionString } from 'mongodb-connection-string-url';
import { createApplication, KitError } from '@arkenivajs/core';

import { mongodbPlugin } from '@arkenivajs/database-mongodb';

interface Customer {
  _id: BSON.ObjectId;
  tenantId: string;
  name: string;
  balance: BSON.Decimal128;
  exact: BSON.Long;
}

/** This application chooses explicit JSON strings for BSON identities, decimals and int64 values. */
export function customerDTO(value: Customer) {
  if (
    !(value._id instanceof BSON.ObjectId) ||
    !(value.balance instanceof BSON.Decimal128) ||
    !(value.exact instanceof BSON.Long) ||
    typeof value.name !== 'string'
  )
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The stored customer requires explicit BSON fields',
    });
  return Object.freeze({
    id: value._id.toHexString(),
    name: value.name,
    balance: value.balance.toString(),
    exact: value.exact.toString(),
  });
}

/** Exercise only randomly owned collections on an explicitly disposable authenticated replica set. */
export async function runMongoDBExample() {
  if (process.env.ARKENIVA_MONGODB_DISPOSABLE !== '1')
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'The MongoDB example requires an explicitly disposable replica set',
    });
  const url = process.env.ARKENIVA_MONGODB_URL;
  if (!url)
    throw new KitError({ code: 'EK_CONFIG_MISSING', message: 'ARKENIVA_MONGODB_URL is required' });
  const app = await createApplication({
    service: { name: 'mongodb-customer-example', version: '1.0.0', environment: 'development' },
    plugins: [mongodbPlugin()],
    databases: { documents: { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_URL' } },
  });
  const name = 'example_' + randomBytes(12).toString('hex'),
    // The application supplies its physical native collection name explicitly; native calls do not apply portable prefixes.
    prefix =
      [...new ConnectionString(url).searchParams].find(
        ([key]) => key.toLowerCase() === 'prefix',
      )?.[1] ?? '',
    tenantId = 'trusted-example-tenant';
  let collection: ReturnType<ReturnType<MongoClient['db']>['collection']> | undefined,
    result:
      | (ReturnType<typeof customerDTO> & {
          changed: number;
          unchanged: number;
          committed: boolean;
          rolledBack: boolean;
        })
      | undefined;
  const failures: unknown[] = [];
  try {
    await app.start();
    const mongo = app.mongo!,
      native = mongo.native();
    assert.ok(native instanceof MongoClient);
    collection = native.db().collection(prefix + name);
    const identity = await mongo.insertOne(name, {
      tenantId,
      name: 'Ada',
      balance: BSON.Decimal128.fromString('1234567890.123456789'),
      exact: BSON.Long.fromString('9007199254740993'),
    });
    const id: unknown = BSON.EJSON.parse(identity, { relaxed: false });
    assert.ok(id instanceof BSON.ObjectId);
    const filter = { _id: id, tenantId },
      row = await mongo.findOne<Customer>(name, filter);
    assert.ok(row);
    const changed = await mongo.updateOne(name, filter, { $set: { name: 'Ada B.' } }),
      unchanged = await mongo.updateOne(name, filter, { $set: { name: 'Ada B.' } });
    assert.equal(changed, 1);
    assert.equal(unchanged, 0);
    assert.equal(
      (await mongo.aggregate(name, [{ $match: { tenantId } }, { $limit: 1 }])).length,
      1,
    );
    let callbacks = 0;
    await mongo.withTransaction(async (session) => {
      assert.ok(session instanceof ClientSession);
      callbacks++;
      await collection!.insertOne({ tenantId, marker: 'committed' }, { session });
    });
    await assert.rejects(
      mongo.withTransaction(async (session) => {
        assert.ok(session instanceof ClientSession);
        callbacks++;
        await collection!.insertOne({ tenantId, marker: 'rolled-back' }, { session });
        throw new Error('The example transaction body rejected');
      }),
      (cause: unknown) => cause instanceof KitError && cause.details.outcome === 'rolled_back',
    );
    assert.equal(callbacks, 2);
    const committed = (await mongo.findOne(name, { tenantId, marker: 'committed' })) !== null,
      rolledBack = (await mongo.findOne(name, { tenantId, marker: 'rolled-back' })) === null;
    assert.ok(committed && rolledBack);
    result = { ...customerDTO(row), changed, unchanged, committed, rolledBack };
  } catch (cause) {
    failures.push(cause);
  } finally {
    try {
      if (collection) await collection.drop();
    } catch (cause) {
      failures.push(cause);
    } finally {
      try {
        await app.stop();
      } catch (cause) {
        failures.push(cause);
      }
    }
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, 'The MongoDB example and cleanup failed');
  assert.ok(result);
  return result;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    console.log(JSON.stringify(await runMongoDBExample()));
  } catch (cause) {
    console.error(
      JSON.stringify(
        cause instanceof KitError
          ? cause.toSafeJSON()
          : { code: 'EK_INTERNAL', message: 'The MongoDB example failed' },
      ),
    );
    process.exitCode = 1;
  }
}
