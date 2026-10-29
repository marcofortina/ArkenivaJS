// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { AuthService, MessageBus } from '@arkenivajs/core';
import { natsNetworkProxy } from '../../../messaging/dist-test/fixtures/network-proxy.js';
import { natsSubscriptionFixture } from '../nats-subscription-fixture.js';

async function eventually(check: () => boolean | Promise<boolean>) {
  const deadline = performance.now() + 5000;
  while (!(await check())) {
    assert.ok(
      performance.now() < deadline,
      'The native subscription recovery exceeded its deadline',
    );
    await delay(5);
  }
}

test(
  'A restarted independent GraphQL process resubscribes to the real broker without replaying old events',
  { timeout: 30000 },
  async () => {
    const namespace = randomBytes(12).toString('hex'),
      publisher = await natsSubscriptionFixture(namespace);
    try {
      const authorization = await publisher.f.token(),
        otherAuthorization = await publisher.f.token('tenant-b');
      for (const generation of [0, 1]) {
        const child = fork(new URL('../nats-subscription-worker.js', import.meta.url), [], {
          stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
        });
        const messages: { kind: string; tenant?: string; frame?: string; active?: number }[] = [];
        child.on('message', (message) => messages.push(message as (typeof messages)[number]));
        const exited = once(child, 'exit');
        try {
          child.send({ namespace, issuer: publisher.f.issuer, authorization, otherAuthorization });
          await eventually(() => {
            assert.equal(child.exitCode, null);
            assert.ok(!messages.some((message) => message.kind === 'failure'));
            return messages.some((message) => message.kind === 'ready');
          });
          await delay(30);
          assert.deepEqual(
            messages.filter((message) => message.kind === 'frame'),
            [],
          );
          await publisher.publish(authorization, 'generation-' + generation);
          await eventually(() => messages.some((message) => message.kind === 'frame'));
          assert.deepEqual(
            messages
              .filter((message) => message.kind === 'frame')
              .map((message) => ({ tenant: message.tenant, frame: JSON.parse(message.frame!) })),
            [
              {
                tenant: 'a',
                frame: {
                  type: 'next',
                  id: 'a',
                  payload: { data: { notice: 'generation-' + generation } },
                },
              },
            ],
          );
        } finally {
          if (child.connected) child.send({ kind: 'close' });
          const timer = setTimeout(() => child.kill('SIGTERM'), 5000);
          timer.unref();
          try {
            const [code] = await exited;
            assert.equal(code, 0);
            assert.ok(
              messages.some((message) => message.kind === 'closed' && message.active === 0),
            );
          } finally {
            clearTimeout(timer);
          }
        }
      }
      assert.deepEqual(publisher.failures, []);
    } finally {
      await publisher.close();
    }
  },
);

test(
  'A lost real broker round trip never replays an uncertain GraphQL event after native mTLS reconnect',
  { timeout: 30000 },
  async () => {
    const proxy = await natsNetworkProxy(),
      variable = 'ARKENIVA_GRAPHQL_NATS_' + randomBytes(12).toString('hex').toUpperCase();
    const url = new URL(process.env.ARKENIVA_NATS_URL!);
    url.hostname = '127.0.0.1';
    url.port = String(proxy.port);
    process.env[variable] = url.href;
    let runtime: Awaited<ReturnType<typeof natsSubscriptionFixture>> | undefined;
    try {
      runtime = await natsSubscriptionFixture(randomBytes(12).toString('hex'), undefined, variable);
      const authorization = await runtime.f.token(),
        socket = await runtime.connect(authorization);
      const frames: unknown[] = [];
      socket.on('message', (frame) => frames.push(JSON.parse(String(frame))));
      socket.send('{"type":"subscribe","id":"one","payload":{"query":"subscription { notice }"}}');
      await eventually(() => runtime!.adapter.stats().acquired === 1);
      await runtime.adapter.ready();
      const auth = runtime.f.app.resolve<AuthService>(COMPONENTS.auth),
        tenant = auth.tenantFrom(await auth.verifyBearer(authorization));
      proxy.pauseReplies();
      await assert.rejects(
        runtime.adapter.port.publish('notices', 'uncertain-event', tenant, { timeoutMs: 100 }),
        (error: unknown) =>
          error instanceof KitError &&
          error.code === 'EK_TIMEOUT' &&
          error.details.outcome === 'unknown',
      );
      assert.deepEqual(frames, []);
      proxy.disconnect();
      proxy.resumeReplies();
      proxy.resume();
      const bus = runtime.f.app.resolve<MessageBus>(COMPONENTS.messaging),
        probe = 'graphql.recovery.' + randomBytes(12).toString('hex');
      // Retry only a separate synthetic transport probe; the uncertain business event is never retried.
      await eventually(async () => {
        try {
          await bus.publish(probe, null, { timeoutMs: 200 });
          return true;
        } catch {
          return false;
        }
      });
      await runtime.adapter.port.publish('notices', 'after-reconnect', tenant);
      await eventually(() => frames.length === 1);
      await delay(40);
      assert.deepEqual(frames, [
        { type: 'next', id: 'one', payload: { data: { notice: 'after-reconnect' } } },
      ]);
      assert.equal(runtime.adapter.stats().active, 1);
      assert.deepEqual(runtime.failures, []);
    } finally {
      proxy.resumeReplies();
      proxy.resume();
      try {
        await runtime?.close();
      } finally {
        delete process.env[variable];
        await proxy.close();
      }
    }
  },
);
