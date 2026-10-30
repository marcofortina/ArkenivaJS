// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { sharedFixture, until } from './shared-fixture.js';

let runtime: Awaited<ReturnType<typeof sharedFixture>> | undefined;
let closing: Promise<void> | undefined;
function close() {
  return (closing ??= (async () => {
    await runtime?.close();
    assert.equal(runtime?.provider.stats().active, 0);
    assert.equal(runtime?.bus.stats().subscriptions, 0);
    process.send?.({
      kind: 'closed',
      active: runtime?.provider.stats().active,
      failures: runtime?.failures(),
    });
    process.disconnect?.();
  })());
}
process.once('disconnect', () => {
  void close().catch(() => {
    process.exitCode = 1;
  });
});
process.once(
  'message',
  (input: {
    namespace: string;
    issuer: string;
    authorization: string;
    otherAuthorization: string;
  }) => {
    void (async () => {
      runtime = await sharedFixture(input.namespace, input.issuer);
      const a = await runtime.connect(input.authorization),
        b = await runtime.connect(input.otherAuthorization);
      await until(() => runtime!.provider.stats().acquired === 2);
      await runtime.provider.ready();
      process.send?.({ kind: 'ready' });
      process.on('message', (message: { kind: string }) => {
        void (async () => {
          if (message.kind === 'inspect') {
            process.send?.({ kind: 'frames', a: a.frames, b: b.frames });
          } else if (message.kind === 'mutate') {
            const response = await runtime!.f.send(
              { query: 'mutation { increment }' },
              input.authorization,
            );
            assert.equal(response.status, 200);
            assert.deepEqual(JSON.parse(response.body), { data: { increment: 1 } });
            process.send?.({ kind: 'mutated' });
          } else if (message.kind === 'close') await close();
          else throw new Error('Unsupported shared counter fixture operation');
        })().catch(async () => {
          process.send?.({ kind: 'failure' });
          process.exitCode = 1;
          await close().catch(() => undefined);
        });
      });
    })().catch(async () => {
      process.send?.({ kind: 'failure' });
      process.exitCode = 1;
      await close().catch(() => undefined);
    });
  },
);
