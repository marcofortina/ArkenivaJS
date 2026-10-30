// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import type { RouteContext } from '@arkenivajs/core';
import type { TenantRegistrySnapshotV1_1 } from '../dist/index.js';
import { fixture, settings } from './http-fixture.js';

assert.ok(process.send, 'The concurrency fixture requires an owned IPC parent');
let owner: Awaited<ReturnType<typeof fixture>> | undefined,
  release: () => void = () => {},
  closing: Promise<void> | undefined;
const close = () =>
  (closing ??= (async () => {
    release();
    await owner?.close();
  })());
process.once('disconnect', () => {
  void close().catch(() => {
    process.exitCode = 1;
  });
});
process.once(
  'message',
  (input: { kind: string; instance: string; snapshot: TenantRegistrySnapshotV1_1 }) => {
    void (async () => {
      assert.equal(input.kind, 'start');
      assert.ok(['first', 'second'].includes(input.instance));
      const effects: { tenant: string; operation: string; id: string }[] = [];
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const base = settings(input.snapshot);
      owner = await fixture({
        ...base,
        handlers: Object.fromEntries(
          Object.entries(base.handlers).map(([name, handler]) => [
            name,
            async (context: RouteContext) => {
              const id = context.params.id ?? (context.body as { id: string }).id;
              effects.push({
                tenant: context.auth!.tenantId,
                operation: context.params.id === undefined ? 'orders.create' : 'orders.read',
                id,
              });
              if (input.instance === 'first' && id === 'held') {
                process.send!({ kind: 'entered' });
                await gate;
              }
              return handler(context);
            },
          ]),
        ),
      });
      const context = await owner.tenant('north');
      process.on('message', (command: { kind: string; id: number }) => {
        if (command.kind === 'release') {
          release();
          process.send!({ kind: 'reply', id: command.id });
        } else if (command.kind === 'snapshot') {
          process.send!({
            kind: 'reply',
            id: command.id,
            effects,
            resolution: owner!.service.api.resolve('orders.read', context),
            state: owner!.app.state,
          });
        } else if (command.kind === 'stop') {
          void close().then(() =>
            process.send!({ kind: 'reply', id: command.id, state: owner!.app.state }, () =>
              process.disconnect!(),
            ),
          );
        }
      });
      process.send!({
        kind: 'ready',
        origin: owner.origin,
        north: await owner.token('north'),
        south: await owner.token('south'),
        pid: process.pid,
      });
    })().catch(async () => {
      process.exitCode = 1;
      await close();
      if (process.connected) process.disconnect!();
    });
  },
);
