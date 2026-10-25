// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { MongoClient, ClientSession } from 'mongodb';
import { createApplication, KitError } from '@arkenivajs/core';
import { mongodbPlugin } from '@arkenivajs/database-mongodb';
import { mongoConfiguration } from '../../dist/config.js';
import { mongoNetworkProxy } from '../fixtures/network-proxy.js';

async function fixture(context: TestContext) {
  assert.equal(process.env.ARKENIVA_MONGODB_DISPOSABLE, '1');
  assert.ok(process.env.ARKENIVA_MONGODB_URL);
  const proxy = await mongoNetworkProxy(),
    url = new URL(process.env.ARKENIVA_MONGODB_URL);
  url.hostname = '127.0.0.1';
  url.port = String(proxy.port);
  const variable = 'ARKENIVA_MONGODB_FAULT_TEST',
    previous = process.env[variable];
  let app;
  try {
    process.env[variable] = url.href;
    app = await createApplication({
      service: { name: 'mongodb-fault-contract', version: '1.0.0', environment: 'test' },
      plugins: [mongodbPlugin()],
      databases: { documents: { driver: 'mongodb', connectionStringEnv: variable } },
    });
    await app.start();
  } finally {
    if (previous === undefined) delete process.env[variable];
    else process.env[variable] = previous;
  }
  const configuration = mongoConfiguration(
    { driver: 'mongodb', connectionStringEnv: 'ARKENIVA_MONGODB_URL' },
    'test',
  );
  const observer = new MongoClient(configuration.url, configuration.native);
  await observer.connect();
  const name = 'fault_' + randomBytes(12).toString('hex'),
    collection = observer.db().collection(configuration.prefix + name);
  await collection.insertOne({ marker: 'seed' });
  let expectCleanupFailure = false;
  context.after(async () => {
    proxy.resumeReplies();
    try {
      await collection.drop();
    } finally {
      try {
        await observer.close();
      } finally {
        try {
          if (expectCleanupFailure)
            await assert.rejects(
              app.stop(),
              (cause: unknown) =>
                cause instanceof KitError &&
                cause.code === 'EK_PLUGIN_FAILED' &&
                cause.cause instanceof AggregateError &&
                cause.cause.errors.some(
                  (failure: unknown) =>
                    failure instanceof KitError && failure.details.cleanupFailed === true,
                ),
            );
          else await app.stop();
        } finally {
          await proxy.close();
        }
      }
    }
  });
  return {
    proxy,
    app,
    mongo: app.mongo!,
    native: app.mongo!.native() as MongoClient,
    name,
    collection,
    expectCleanupFailure() {
      expectCleanupFailure = true;
    },
  };
}

test('Real MongoDB lost insert acknowledgments report unknown effects without replaying the mutation', async (context) => {
  const f = await fixture(context);
  let submissions = 0;
  f.native.on('commandStarted', (event) => {
    if (event.commandName === 'insert') {
      submissions++;
      f.proxy.dropReplies();
    }
  });
  await assert.rejects(
    f.mongo.insertOne(f.name, { marker: 'lost-insert' }, { timeoutMs: 500 }),
    (cause: unknown) =>
      cause instanceof KitError && cause.details.outcome === 'unknown' && cause.retryable === false,
  );
  f.proxy.resumeReplies();
  assert.equal(submissions, 1);
  assert.equal(await f.collection.countDocuments({ marker: 'lost-insert' }), 1);
});

test('Real MongoDB lost commit acknowledgments never replay the callback and retain the committed unknown outcome', async (context) => {
  const f = await fixture(context);
  let callbacks = 0,
    commits = 0,
    session: ClientSession | undefined;
  const nativeCollection = f.native.db().collection(f.collection.collectionName);
  f.native.on('commandStarted', (event) => {
    if (event.commandName === 'commitTransaction') {
      commits++;
      f.proxy.dropReplies();
    }
  });
  await assert.rejects(
    f.mongo.withTransaction(
      async (value) => {
        assert.ok(value instanceof ClientSession);
        session = value;
        callbacks++;
        await nativeCollection.insertOne({ marker: 'lost-commit' }, { session: value });
        return 42;
      },
      { timeoutMs: 500 },
    ),
    (cause: unknown) =>
      cause instanceof KitError && cause.details.outcome === 'unknown' && cause.retryable === false,
  );
  f.proxy.resumeReplies();
  assert.equal(callbacks, 1);
  assert.equal(commits, 1);
  assert.equal(await f.collection.countDocuments({ marker: 'lost-commit' }), 1);
  // The native commit can settle just after the public deadline; framework ownership remains observable.
  const deadline = performance.now() + 3000;
  while (!session?.hasEnded) {
    assert.ok(performance.now() < deadline, 'The owned native session did not finish');
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
});

test('Real MongoDB read cancellation closes its own stalled request without blocking an independent application', async (context) => {
  const f = await fixture(context),
    controller = new AbortController();
  f.native.on('commandStarted', (event) => {
    if (event.commandName === 'find') {
      f.proxy.dropReplies();
      setTimeout(() => controller.abort(), 25);
    }
  });
  await assert.rejects(
    f.mongo.findMany(f.name, {}, { signal: controller.signal, timeoutMs: 1000 }),
    { code: 'EK_ABORTED' },
  );
  f.proxy.resumeReplies();
  assert.ok(await f.collection.findOne({ marker: 'seed' }));
});

test(
  'Real MongoDB missing rollback acknowledgments expose cleanup uncertainty even when the native SDK suppresses abort errors',
  { timeout: 15000 },
  async (context) => {
    const f = await fixture(context),
      collection = f.native.db().collection(f.collection.collectionName);
    let aborts = 0;
    f.native.on('commandStarted', (event) => {
      if (event.commandName === 'abortTransaction') {
        aborts++;
        f.proxy.dropReplies();
      }
    });
    f.expectCleanupFailure();
    try {
      await assert.rejects(
        f.mongo.withTransaction(
          async (value) => {
            assert.ok(value instanceof ClientSession);
            await collection.insertOne({ marker: 'lost-rollback' }, { session: value });
            throw new Error('The application callback rejected');
          },
          { timeoutMs: 10000 },
        ),
        (cause: unknown) =>
          cause instanceof KitError &&
          cause.details.cleanupFailed === true &&
          cause.details.outcome === 'unknown' &&
          cause.retryable === false,
      );
    } finally {
      f.proxy.resumeReplies();
    }
    assert.ok(
      aborts >= 1 && aborts <= 2,
      'Native rollback cleanup exceeded its single retry bound',
    );
    assert.equal(await f.collection.countDocuments({ marker: 'lost-rollback' }), 0);
  },
);
