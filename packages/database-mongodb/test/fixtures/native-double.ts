// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { TestContext } from 'node:test';
import { MongoClient, Db, Collection, AbstractCursor, BSON } from 'mongodb';
import type { Document } from 'mongodb';
import { MongoConnection } from '../../dist/connection.js';
import type { MongoObservationPorts } from '../../dist/connection.js';

export interface Plan {
  readonly value?: unknown;
  readonly error?: unknown;
  readonly fail?: boolean;
  readonly gate?: Promise<void>;
}

/** Only exported SDK method boundaries are doubled; actual SDK clients/cursors and real-server suites remain independent. */
export function nativeDouble(context: TestContext, observation: MongoObservationPorts = {}) {
  const plans = new Map<string, Plan[]>(),
    calls: { method: string; payload: unknown; options: unknown }[] = [];
  async function execute(
    method: string,
    payload: unknown,
    options: unknown,
    defaultValue: unknown,
  ) {
    calls.push({ method, payload, options });
    const plan = plans.get(method)?.shift();
    if (plan?.gate) await plan.gate;
    if (plan?.fail) throw plan.error;
    return plan && 'value' in plan ? plan.value : defaultValue;
  }
  context.mock.method(MongoClient.prototype, 'connect', async function (this: MongoClient) {
    await execute('connect', undefined, undefined, undefined);
    return this;
  });
  context.mock.method(Db.prototype, 'command', async (document: Document, options: unknown) =>
    execute('command', document, options, { ok: 1, setName: 'unit' }),
  );
  context.mock.method(AbstractCursor.prototype, 'next', async () =>
    execute('next', undefined, undefined, null),
  );
  context.mock.method(
    Collection.prototype,
    'insertOne',
    async (document: Document, options: unknown) =>
      execute('insertOne', document, options, {
        acknowledged: true,
        insertedId: document._id ?? new BSON.ObjectId(),
      }),
  );
  context.mock.method(
    Collection.prototype,
    'updateOne',
    async (filter: Document, update: Document, options: unknown) =>
      execute('updateOne', { filter, update }, options, {
        acknowledged: true,
        matchedCount: 1,
        modifiedCount: 1,
        upsertedCount: 0,
        upsertedId: null,
      }),
  );
  context.mock.method(
    Collection.prototype,
    'deleteOne',
    async (filter: Document, options: unknown) =>
      execute('deleteOne', filter, options, { acknowledged: true, deletedCount: 1 }),
  );
  const connection = new MongoConnection(
    'test',
    {
      url: 'mongodb://127.0.0.1:1/unit',
      database: 'unit',
      prefix: 'scope_',
      native: { retryReads: false, retryWrites: false, maxAdaptiveRetries: 0 },
    },
    observation,
  );
  let expectedCloseFailure = false;
  context.after(async () => {
    try {
      await connection.close();
    } catch (cause) {
      if (!expectedCloseFailure) throw cause;
    }
  });
  return {
    connection,
    calls,
    plan(method: string, plan: Plan) {
      const queue = plans.get(method) ?? [];
      queue.push(plan);
      plans.set(method, queue);
    },
    allowCloseFailure() {
      expectedCloseFailure = true;
    },
  };
}

export function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
