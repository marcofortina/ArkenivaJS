// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { subscribe, parse } from 'graphql';
import type { ExecutionResult } from 'graphql';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';
import type { GraphqlFieldAuthorization, GraphqlSubscriptionSource } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';
import { compileSchema } from '../../dist/schema.js';
import { OwnedContexts } from '../../dist/contexts.js';
import { Operation } from '../../dist/operation.js';
import { protectFields } from '../../dist/fields.js';
import { installMetadata } from '../../dist/metadata.js';
import { SubscriptionExecution } from '../../dist/subscription-execution.js';
import { fixture } from '../fixture.js';

async function runtime(
  source: GraphqlSubscriptionSource,
  authorize: GraphqlFieldAuthorization,
  maxOperationMs = 30000,
  list = false,
) {
  const f = await fixture();
  try {
    const authority = f.app.resolve<AuthService>(COMPONENTS.auth),
      token = await f.token();
    const identity = await authority.verifyBearer(token),
      principal = authority.tenantFrom(identity);
    let mappings = 0;
    const settings = capture({
      schema: `type Event { value: String! secret: String } type Query { ping: String } type Subscription { notice: ${list ? '[Event!]!' : 'Event!'} }`,
      resolvers: {
        Subscription: {
          notice: {
            subscribe: source,
            resolve(parent) {
              mappings++;
              return parent;
            },
          },
        },
      },
      security: {
        auth: { required: true, scopes: ['graphql:read'] },
        authorizeField: authorize,
        limits: { maxFieldExecutions: 3, maxOperationMs },
      },
    });
    const schema = compileSchema(settings),
      scopes = new OwnedContexts<Operation>(),
      executions = new OwnedContexts<SubscriptionExecution>();
    protectFields(schema, settings, scopes, executions);
    installMetadata();
    const owner = new AbortController();
    const execution = new SubscriptionExecution(
      settings,
      authority,
      token,
      principal,
      { requestId: 'native-subscription' },
      owner.signal,
    );
    const context = {};
    execution.bind(context, scopes);
    const release = executions.bind(context, () => execution);
    await execution.prepare();
    return {
      f,
      execution,
      owner,
      authority,
      principal,
      settings,
      token,
      mappings: () => mappings,
      async start(query: string) {
        return subscribe({ schema, document: parse(query), contextValue: { ...context } });
      },
      async close() {
        await execution.close();
        release();
        await f.close();
      },
    };
  } catch (error) {
    await f.close();
    throw error;
  }
}

function iterator(
  result: Awaited<ReturnType<typeof subscribe>>,
): AsyncIterableIterator<ExecutionResult> {
  assert.ok(Symbol.asyncIterator in result, 'The native executor must establish an async source');
  return result as AsyncIterableIterator<ExecutionResult>;
}
const decoded = (input: unknown) =>
  JSON.parse(JSON.stringify(input)) as {
    data: { notice: { value: string; secret?: string | null; __typename?: string } } | null;
    errors?: readonly { extensions?: { code?: string } }[];
  };

test('Native subscription events receive fresh verified scopes, independent field caps and guarded metadata across copied contexts', async () => {
  const contexts: object[] = [],
    fields: string[] = [];
  let closes = 0;
  const r = await runtime(
    async function* (_parent, _args, context) {
      assert.equal(context.auth?.tenantId, 'tenant-a');
      try {
        yield { value: 'first' };
        yield { value: 'second' };
      } finally {
        closes++;
      }
    },
    ({ context, field }) => {
      assert.equal(context.auth?.tenantId, 'tenant-a');
      contexts.push(context);
      fields.push(field.fieldName);
      return true;
    },
  );
  try {
    const values = iterator(await r.start('subscription { notice { value __typename } }'));
    const first = decoded((await values.next()).value);
    const firstScope = r.execution.current;
    assert.deepEqual(first, { data: { notice: { value: 'first', __typename: 'Event' } } });
    assert.equal(firstScope?.fields, 3);
    const second = decoded((await values.next()).value);
    assert.deepEqual(second, { data: { notice: { value: 'second', __typename: 'Event' } } });
    assert.notEqual(r.execution.current, firstScope);
    assert.equal(r.execution.current?.fields, 3);
    assert.equal(r.mappings(), 2);
    assert.equal(
      new Set(contexts).size,
      3,
      'Source authorization and both events have distinct contexts',
    );
    assert.equal(fields.filter((field) => field === '__typename').length, 2);
    await values.return?.();
    await r.execution.completion;
    assert.equal(closes, 1);
    assert.equal(r.execution.current, undefined);
  } finally {
    await r.close();
  }
});

test('Every event authorizes root mappings and default property reads before private getters execute', async () => {
  let privateReads = 0,
    reads = 0,
    permit = true;
  const event = {
    get value() {
      reads++;
      return 'allowed';
    },
    get secret() {
      privateReads++;
      return 'private';
    },
  };
  const r = await runtime(
    async function* () {
      yield event;
      yield event;
    },
    ({ field }) => permit && field.fieldName !== 'secret',
  );
  try {
    const values = iterator(await r.start('subscription { notice { value secret } }'));
    const first = decoded((await values.next()).value);
    assert.deepEqual(first.data, { notice: { value: 'allowed', secret: null } });
    assert.equal(first.errors?.[0]?.extensions?.code, 'EK_GQL_FORBIDDEN');
    assert.equal(privateReads, 0);
    assert.equal(reads, 1);
    permit = false;
    const second = decoded((await values.next()).value);
    assert.equal(second.data, null);
    assert.equal(second.errors?.[0]?.extensions?.code, 'EK_GQL_FORBIDDEN');
    assert.equal(privateReads, 0);
    assert.equal(reads, 1);
    assert.equal(r.mappings(), 1);
    await values.return?.();
  } finally {
    await r.close();
  }
});

test('Denied source authorization allocates no application iterator', async () => {
  let allocations = 0;
  const r = await runtime(
    async function* () {
      allocations++;
      yield { value: 'never' };
    },
    () => false,
  );
  try {
    const result = await r.start('subscription { notice { value } }');
    assert.ok(!('next' in result));
    assert.equal(result.errors?.[0]?.extensions?.code, 'EK_GQL_FORBIDDEN');
    await r.execution.completion;
    assert.equal(allocations, 0);
  } finally {
    await r.close();
  }
});

test('A failed real authentication authority blocks the next event before mapping or getters', async () => {
  let reads = 0,
    closes = 0;
  const r = await runtime(
    async function* () {
      try {
        yield {
          get value() {
            reads++;
            return 'first';
          },
        };
        yield {
          get value() {
            reads++;
            return 'forbidden';
          },
        };
      } finally {
        closes++;
      }
    },
    () => true,
  );
  try {
    const values = iterator(await r.start('subscription { notice { value } }'));
    assert.equal(decoded((await values.next()).value).data?.notice.value, 'first');
    await r.f.app.stop();
    await assert.rejects(
      values.next(),
      (error: unknown) => error instanceof KitError && error.code === 'EK_GQL_SUBSCRIPTION',
    );
    await r.execution.completion;
    assert.equal(reads, 1);
    assert.equal(r.mappings(), 1);
    assert.equal(closes, 1);
  } finally {
    await r.close();
  }
});

test(
  'A timed-out source still retires its late iterator before physical execution ownership completes',
  { timeout: 5000 },
  async () => {
    let provide!: (source: AsyncIterable<unknown>) => void;
    const pending = new Promise<AsyncIterable<unknown>>((resolve) => {
      provide = resolve;
    });
    let closes = 0,
      completed = false;
    let signal: AbortSignal | undefined;
    const r = await runtime(
      (_parent, _args, context) => {
        signal = context.signal;
        return pending;
      },
      () => true,
      200,
    );
    try {
      void r.execution.completion.then(() => {
        completed = true;
      });
      const result = await r.start('subscription { notice { value } }');
      assert.ok(!('next' in result));
      assert.equal(result.errors?.[0]?.extensions?.code, 'EK_GQL_TIMEOUT');
      assert.equal(signal?.aborted, true);
      assert.equal(completed, false);
      provide({
        [Symbol.asyncIterator]() {
          return {
            async next() {
              return { done: true, value: undefined };
            },
            async return() {
              closes++;
              return { done: true, value: undefined };
            },
          };
        },
      });
      await r.execution.completion;
      assert.equal(closes, 1);
      assert.equal(completed, true);
      assert.equal(r.mappings(), 0);
    } finally {
      await r.close();
    }
  },
);

test('Copied principals, a different valid tenant and missing scopes never establish a trusted subscription execution', async () => {
  let allocations = 0;
  const r = await runtime(
    async function* () {
      allocations++;
      yield { value: 'never' };
    },
    () => true,
  );
  const extra: SubscriptionExecution[] = [];
  try {
    assert.throws(
      () =>
        new SubscriptionExecution(
          r.settings,
          r.authority,
          r.token,
          { ...r.principal },
          { requestId: 'copied' },
          new AbortController().signal,
        ),
      (error: unknown) => error instanceof KitError && error.code === 'EK_GQL_AUTH',
    );
    const otherIdentity = await r.authority.verifyBearer(await r.f.token('tenant-b'));
    const other = new SubscriptionExecution(
      r.settings,
      r.authority,
      r.token,
      r.authority.tenantFrom(otherIdentity),
      { requestId: 'foreign' },
      new AbortController().signal,
    );
    extra.push(other);
    await assert.rejects(
      other.prepare(),
      (error: unknown) => error instanceof KitError && error.code === 'EK_GQL_AUTH',
    );
    const unscopedToken = await r.f.token('tenant-a', 'other:scope');
    const unscopedIdentity = await r.authority.verifyBearer(unscopedToken);
    const unscoped = new SubscriptionExecution(
      r.settings,
      r.authority,
      unscopedToken,
      r.authority.tenantFrom(unscopedIdentity),
      { requestId: 'unscoped' },
      new AbortController().signal,
    );
    extra.push(unscoped);
    await assert.rejects(
      unscoped.prepare(),
      (error: unknown) => error instanceof KitError && error.code === 'EK_GQL_AUTH',
    );
    assert.equal(allocations, 0);
  } finally {
    await Promise.all(extra.map((execution) => execution.close()));
    await r.close();
  }
});

test(
  'An idle subscription can outlive one operation deadline while its next event receives a new bounded execution',
  { timeout: 5000 },
  async () => {
    const r = await runtime(
      async function* () {
        yield { value: 'after-idle' };
      },
      () => true,
      200,
    );
    try {
      const values = iterator(await r.start('subscription { notice { value } }'));
      await delay(225);
      assert.equal(decoded((await values.next()).value).data?.notice.value, 'after-idle');
      assert.equal(r.execution.current?.controller.signal.aborted, false);
      await values.return?.();
    } finally {
      await r.close();
    }
  },
);

test('List subscription sources remain iterators while each event enforces its own collection limit without truncation', async () => {
  let reads = 0;
  const item = () => ({
    get value() {
      reads++;
      return 'bounded';
    },
  });
  const r = await runtime(
    async function* () {
      yield [item(), item()];
      yield Array.from({ length: 101 }, item);
    },
    () => true,
    30000,
    true,
  );
  try {
    const values = iterator(await r.start('subscription { notice { value } }'));
    const first = JSON.parse(JSON.stringify((await values.next()).value)) as {
      data: { notice: { value: string }[] };
    };
    assert.deepEqual(first, { data: { notice: [{ value: 'bounded' }, { value: 'bounded' }] } });
    const second = decoded((await values.next()).value);
    assert.equal(second.data, null);
    assert.equal(second.errors?.[0]?.extensions?.code, 'EK_GQL_COMPLEXITY');
    assert.equal(reads, 2, 'An oversized event must fail before any child getter executes');
    await values.return?.();
  } finally {
    await r.close();
  }
});
