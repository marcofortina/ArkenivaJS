// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { natsSubscriptionFixture } from '../nats-subscription-fixture.js';
import { COMPONENTS } from '@arkenivajs/core';
import type { AuthService } from '@arkenivajs/core';

test(
  'Actual mTLS NATS delivers tenant-bound public GraphQL subscriptions across independent Node processes',
  { timeout: 20000 },
  async () => {
    const namespace = randomBytes(12).toString('hex'),
      r = await natsSubscriptionFixture(namespace);
    const child = fork(new URL('../nats-subscription-worker.js', import.meta.url), [], {
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    const messages: {
      kind: string;
      tenant?: string;
      frame?: string;
      active?: number;
      failures?: number;
    }[] = [];
    child.on('message', (message) => messages.push(message as (typeof messages)[number]));
    const exited = once(child, 'exit');
    const wait = async (predicate: () => boolean) => {
      const deadline = performance.now() + 5000;
      while (!predicate()) {
        assert.equal(child.exitCode, null, 'The independent GraphQL process exited prematurely');
        assert.equal(
          messages.some((message) => message.kind === 'failure'),
          false,
          'The independent GraphQL process failed',
        );
        assert.ok(
          performance.now() < deadline,
          'The broker integration exceeded its delivery budget',
        );
        await delay(5);
      }
    };
    try {
      const authorization = await r.f.token(),
        otherAuthorization = await r.f.token('tenant-b');
      child.send({ namespace, issuer: r.f.issuer, authorization, otherAuthorization });
      const socket = await r.connect(authorization);
      socket.send(
        JSON.stringify({
          type: 'subscribe',
          id: 'local',
          payload: { query: 'subscription { notice(tenantHint:"tenant-b") }' },
        }),
      );
      await wait(
        () =>
          messages.some((message) => message.kind === 'ready') && r.adapter.stats().acquired === 1,
      );
      await r.adapter.ready();
      const local = once(socket, 'message');
      await r.publish(authorization, 'tenant-a-event');
      assert.deepEqual(JSON.parse(String((await local)[0])), {
        type: 'next',
        id: 'local',
        payload: { data: { notice: 'tenant-a-event' } },
      });
      await wait(() =>
        messages.some((message) => message.kind === 'frame' && message.tenant === 'a'),
      );
      await r.publish(otherAuthorization, 'tenant-b-event');
      await wait(() =>
        messages.some((message) => message.kind === 'frame' && message.tenant === 'b'),
      );
      await delay(40);
      assert.deepEqual(
        messages
          .filter((message) => message.kind === 'frame')
          .map((message) => ({ tenant: message.tenant, frame: JSON.parse(message.frame!) })),
        [
          {
            tenant: 'a',
            frame: { type: 'next', id: 'a', payload: { data: { notice: 'tenant-a-event' } } },
          },
          {
            tenant: 'b',
            frame: { type: 'next', id: 'b', payload: { data: { notice: 'tenant-b-event' } } },
          },
        ],
      );
      const auth = r.f.app.resolve<AuthService>(COMPONENTS.auth),
        tenant = auth.tenantFrom(await auth.verifyBearer(authorization));
      await assert.rejects(r.adapter.port.publish('notices', 'forged', { ...tenant }));
      await assert.rejects(r.adapter.port.publish('foreign-topic', 'forged', tenant));
      assert.throws(() => r.adapter.port.subscribe('notices', { ...tenant }));
      assert.throws(() => r.adapter.port.subscribe('foreign-topic', tenant));
      assert.equal(r.adapter.stats().acquired, 1);
      assert.deepEqual(r.failures, []);
    } finally {
      if (child.connected) child.send({ kind: 'close' });
      const timer = setTimeout(() => child.kill('SIGTERM'), 5000);
      timer.unref();
      try {
        const [code] = await exited;
        assert.equal(code, 0);
        assert.ok(
          messages.some(
            (message) =>
              message.kind === 'closed' && message.active === 0 && message.failures === 0,
          ),
        );
      } finally {
        clearTimeout(timer);
        await r.close();
      }
      assert.equal(r.adapter.stats().active, 0);
      assert.equal(r.f.service.stats().activeSubscriptions, 0);
    }
  },
);
