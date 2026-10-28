// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { messagingPlugin } from '@arkenivajs/messaging';
import { redisPlugin } from '@arkenivajs/database-redis';
import { fixture } from './fixture.js';

export async function sharedProcess(provider: 'redis' | 'nats') {
  const redis = provider === 'redis',
    failures: unknown[] = [];
  const f = await fixture(
    { pubsub: { provider, connectionName: redis ? 'shared' : 'messaging' } },
    undefined,
    [
      redis
        ? redisPlugin()
        : messagingPlugin({
            connectionStringEnv: 'ARKENIVA_NATS_URL',
            onError: async (error) => {
              failures.push(error);
            },
          }),
    ],
    redis
      ? { databases: { shared: { driver: 'redis', connectionStringEnv: 'ARKENIVA_REDIS_URL' } } }
      : {},
  );
  const child = fork(new URL('./broker-worker.js', import.meta.url), [], {
    stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  const messages: { kind: string; tenant?: string; frame?: string }[] = [];
  child.on('message', (message) => {
    messages.push(message as (typeof messages)[number]);
  });
  const exited = once(child, 'exit');
  const wait = async (predicate: () => boolean) => {
    const until = performance.now() + 5000;
    while (!predicate()) {
      assert.equal(child.exitCode, null, 'The independent realtime process exited before delivery');
      assert.equal(
        messages.some((message) => message.kind === 'failure'),
        false,
        'The independent realtime process failed',
      );
      assert.ok(
        performance.now() < until,
        'The independent realtime process exceeded its delivery budget',
      );
      await delay(5);
    }
  };
  try {
    const authorization = await f.token();
    child.send({
      provider,
      issuer: f.issuer,
      authorization,
      otherAuthorization: await f.token('tenant-b'),
    });
    await wait(() => messages.some((message) => message.kind === 'ready'));
    const tenant = f.app.auth!.tenantFrom(await f.app.auth!.verifyBearer(authorization));
    await f.service.publish('cross-process', new Uint8Array([1, 128, 255]), tenant);
    await wait(() => messages.some((message) => message.kind === 'frame'));
    await delay(40);
    assert.deepEqual(
      messages.filter((message) => message.kind === 'frame'),
      [{ kind: 'frame', tenant: 'a', frame: '{"channel":"cross-process","payload":"AYD_"}' }],
    );
    assert.deepEqual(failures, []);
  } finally {
    if (child.connected) child.send({ kind: 'close' });
    const timer = setTimeout(() => child.kill('SIGTERM'), 5000);
    timer.unref();
    try {
      const [code] = await exited;
      assert.equal(code, 0);
    } finally {
      clearTimeout(timer);
      await f.close();
    }
  }
}
