// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSchema } from 'graphql';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';
import type { GraphqlRequestContext } from '../../dist/index.js';
import { capture } from '../../dist/policy.js';
import { SubscriptionAdmission } from '../../dist/subscription-admission.js';
import { subscriptionFrame } from '../../dist/subscription-ingress.js';
import { fixture } from '../fixture.js';

const settings = capture({
  schema: 'type Query { ping: String } type Subscription { notice: String }',
  resolvers: {},
  security: { authorizeField: () => false },
  subscriptions: {
    enabled: true,
    pubsub: {
      subscribe() {
        throw new Error('Admission must not allocate a source');
      },
      async publish() {
        throw new Error('Admission must not publish');
      },
      async close() {},
    },
    maxConnections: 2,
    maxOperationsPerConnection: 2,
    maxQueuedEventsPerConnection: 2,
    revalidateIntervalMs: 1000,
    allowedOrigins: ['https://portal.example.test'],
  },
});
const schema = buildSchema(settings.schema);
const frame = (input: unknown) =>
  subscriptionFrame(Buffer.from(JSON.stringify(input)), false, settings.security.limits);
const start = (id: string) =>
  frame({ type: 'subscribe', id, payload: { query: 'subscription { notice }' } });
const stop = (id: string) => frame({ type: 'complete', id });
const rejected = (work: () => unknown, code: string) =>
  assert.throws(work, (error: unknown) => error instanceof KitError && error.code === code);

async function authenticated() {
  const f = await fixture();
  try {
    const authority = f.app.resolve<AuthService>(COMPONENTS.auth),
      authorization = await f.token();
    const identity = await authority.verifyBearer(authorization);
    const context: GraphqlRequestContext = Object.freeze({
      requestId: 'owned-subscription',
      signal: new AbortController().signal,
      identity,
      auth: authority.tenantFrom(identity),
    });
    const admission = () => new SubscriptionAdmission(schema, settings, authority);
    const ready = () => {
      const result = admission();
      result.accept(frame({ type: 'connection_init', payload: { authorization } }));
      assert.equal(result.authorization(), authorization);
      result.authenticate(context);
      result.acknowledge();
      return result;
    };
    return { f, context, admission, ready, authorization };
  } catch (error) {
    await f.close();
    throw error;
  }
}

test('Native subscription admission requires authenticated provenance and the actual ACK before starts', async () => {
  const f = await authenticated();
  try {
    const admission = f.admission();
    rejected(() => admission.accept(start('before-init')), 'EK_GQL_AUTH');
    rejected(() => admission.acknowledge(), 'EK_GQL_SUBSCRIPTION');
    admission.accept(
      frame({ type: 'connection_init', payload: { authorization: f.authorization } }),
    );
    rejected(() => admission.accept(start('before-auth')), 'EK_GQL_AUTH');
    rejected(
      () =>
        admission.accept(
          frame({ type: 'connection_init', payload: { authorization: f.authorization } }),
        ),
      'EK_GQL_SUBSCRIPTION',
    );
    rejected(
      () => admission.authenticate({ ...f.context, identity: { ...f.context.identity! } }),
      'EK_GQL_AUTH',
    );
    rejected(
      () => admission.authenticate({ ...f.context, auth: { ...f.context.auth! } }),
      'EK_GQL_AUTH',
    );
    admission.authenticate(f.context);
    rejected(() => admission.authorization(), 'EK_GQL_AUTH');
    rejected(() => admission.accept(start('before-ack')), 'EK_GQL_AUTH');
    admission.acknowledge();
    assert.deepEqual(admission.stats(), { activeOperations: 0, pendingFrames: 0 });
    admission.accept(start('accepted'));
    assert.deepEqual(admission.stats(), { activeOperations: 1, pendingFrames: 1 });
    rejected(() => admission.accept(start('accepted')), 'EK_GQL_SUBSCRIPTION');
    admission.retire('accepted');
    admission.close();
  } finally {
    await f.f.close();
  }
});

test('Operation and hidden native-frame capacity remains charged through stop and logical connection closure', async () => {
  const f = await authenticated();
  try {
    const admission = f.ready();
    admission.accept(start('one'));
    admission.accept(start('two'));
    rejected(() => admission.accept(start('three')), 'EK_GQL_BACKPRESSURE');
    assert.equal(admission.parsed('one').input.query, 'subscription { notice }');
    admission.parsed('one');
    assert.deepEqual(admission.stats(), { activeOperations: 2, pendingFrames: 1 });
    rejected(() => admission.accept(start('three')), 'EK_GQL_BACKPRESSURE');
    assert.equal(admission.accept(stop('one')), undefined);
    assert.equal(admission.accept(stop('one')), false);
    assert.equal(admission.accept(stop('unknown')), false);
    assert.deepEqual(admission.stats(), { activeOperations: 2, pendingFrames: 2 });
    admission.retire('one');
    assert.deepEqual(admission.stats(), { activeOperations: 1, pendingFrames: 1 });
    admission.accept(start('three'));
    admission.close();
    admission.close();
    assert.deepEqual(admission.stats(), { activeOperations: 2, pendingFrames: 2 });
    rejected(() => admission.accept(start('four')), 'EK_GQL_SUBSCRIPTION');
    rejected(() => admission.parsed('two'), 'EK_GQL_SUBSCRIPTION');
    admission.retire('two');
    admission.retire('three');
    admission.retire('three');
    assert.deepEqual(admission.stats(), { activeOperations: 0, pendingFrames: 0 });
  } finally {
    await f.f.close();
  }
});

test('Pending heartbeat frames share the bounded ingress budget and ignored completion races allocate nothing', async () => {
  const f = await authenticated();
  try {
    const admission = f.ready();
    admission.accept(frame({ type: 'ping' }));
    admission.accept(frame({ type: 'ping' }));
    rejected(() => admission.accept(frame({ type: 'ping' })), 'EK_GQL_BACKPRESSURE');
    rejected(() => admission.accept(start('full')), 'EK_GQL_BACKPRESSURE');
    assert.equal(admission.accept(frame({ type: 'pong' })), false);
    assert.equal(admission.accept(stop('finished-before-client-stop')), false);
    assert.deepEqual(admission.stats(), { activeOperations: 0, pendingFrames: 2 });
    admission.sentPong();
    admission.accept(start('now-admitted'));
    assert.deepEqual(admission.stats(), { activeOperations: 1, pendingFrames: 2 });
    admission.close();
    admission.sentPong();
    assert.deepEqual(admission.stats(), { activeOperations: 1, pendingFrames: 1 });
    admission.retire('now-admitted');
    assert.deepEqual(admission.stats(), { activeOperations: 0, pendingFrames: 0 });
  } finally {
    await f.f.close();
  }
});

test('Failed validation and unavailable authentication authority never create an operation reservation', async () => {
  const f = await authenticated();
  try {
    const admission = f.ready();
    for (const query of [
      '{ ping }',
      'subscription { absent }',
      'subscription { ...Cycle } fragment Cycle on Subscription { ...Cycle }',
    ]) {
      rejected(
        () => admission.accept(frame({ type: 'subscribe', id: 'denied', payload: { query } })),
        'EK_GQL_VALIDATION',
      );
      assert.deepEqual(admission.stats(), { activeOperations: 0, pendingFrames: 0 });
    }
    const pending = f.admission();
    pending.accept(frame({ type: 'connection_init', payload: { authorization: f.authorization } }));
    await f.f.app.stop();
    rejected(() => pending.authenticate(f.context), 'EK_GQL_AUTH');
    rejected(() => pending.accept(start('unavailable')), 'EK_GQL_AUTH');
    pending.close();
    assert.deepEqual(pending.stats(), { activeOperations: 0, pendingFrames: 0 });
    admission.close();
  } finally {
    await f.f.close();
  }
});
