// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createApplication } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';

const service = { name: 'mongodb-contract', version: '1.0.0', environment: 'test' as const };
test('MongoDB prepares a frozen typed facade without resolving secrets and stale handles stay closed', async () => {
  const app = await createApplication({
    service,
    plugins: [mongodbPlugin()],
    databases: {
      documents: { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_NEVER_RESOLVED' },
    },
  });
  const mongo = app.mongo!;
  assert.equal(Object.isFrozen(mongo), true);
  assert.throws(() => mongo.native(), { code: 'EK_LIFECYCLE_STATE' });
  for (const call of [
    () => mongo.findOne('records', {}),
    () => mongo.findMany('records', {}),
    () => mongo.insertOne('records', {}),
    () => mongo.updateOne('records', {}, { $set: { value: 1 } }),
    () => mongo.deleteOne('records', {}),
    () => mongo.aggregate('records', [{ $limit: 1 }]),
    () => mongo.withTransaction(async () => 1),
  ])
    await assert.rejects(call, { code: 'EK_LIFECYCLE_STATE' });
  await app.stop();
  await assert.rejects(mongo.findOne('records', {}), { code: 'EK_RESOURCE_CLOSED' });
  assert.throws(() => mongo.native(), { code: 'EK_RESOURCE_CLOSED' });
});

test('MongoDB rejects missing and duplicate singleton definitions and SQL pool options without connecting', async () => {
  const app = await createApplication({ service, plugins: [mongodbPlugin()] });
  await assert.rejects(app.start());
  await app.stop();
  for (const databases of [
    {
      one: { driver: 'mongodb' as const, connectionStringEnv: 'MONGO_UNSET' },
      two: { driver: 'mongodb' as const, connectionStringEnv: 'MONGO_UNSET' },
    },
    { one: { driver: 'mongodb' as const, connectionStringEnv: 'MONGO_UNSET', poolMax: 8 } },
  ])
    await assert.rejects(createApplication({ service, plugins: [mongodbPlugin()], databases }), {
      code: 'EK_CONFIG_INVALID',
    });
});
