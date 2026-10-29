// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';
import { natsSubscriptionFixture } from './nats-subscription-fixture.js';

interface Start {
  readonly namespace: string;
  readonly issuer: string;
  readonly authorization: string;
  readonly otherAuthorization: string;
}
let runtime: Awaited<ReturnType<typeof natsSubscriptionFixture>> | undefined;
let closing: Promise<void> | undefined;
function close() {
  return (closing ??= (async () => {
    await runtime?.close();
    assert.equal(runtime?.adapter.stats().active, 0);
    process.send?.({
      kind: 'closed',
      active: runtime?.adapter.stats().active,
      failures: runtime?.failures.length,
    });
    process.disconnect?.();
  })());
}
process.once('disconnect', () => {
  void close().catch(() => {
    process.exitCode = 1;
  });
});
process.once('message', (input: Start) => {
  void (async () => {
    runtime = await natsSubscriptionFixture(input.namespace, input.issuer);
    for (const [tenant, authorization] of [
      ['a', input.authorization],
      ['b', input.otherAuthorization],
    ] as const) {
      const socket = await runtime.connect(authorization);
      socket.on('message', (frame) =>
        process.send?.({ kind: 'frame', tenant, frame: String(frame) }),
      );
      socket.send(
        JSON.stringify({
          type: 'subscribe',
          id: tenant,
          payload: { query: 'subscription { notice(tenantHint:"spoofed") }' },
        }),
      );
    }
    const deadline = performance.now() + 5000;
    while (runtime.adapter.stats().acquired !== 2) {
      assert.ok(performance.now() < deadline);
      await delay(5);
    }
    await runtime.adapter.ready();
    process.send?.({ kind: 'ready' });
    process.once('message', () => {
      void close().catch(() => {
        process.exitCode = 1;
      });
    });
  })().catch(async () => {
    process.send?.({ kind: 'failure' });
    process.exitCode = 1;
    await close().catch(() => undefined);
  });
});
