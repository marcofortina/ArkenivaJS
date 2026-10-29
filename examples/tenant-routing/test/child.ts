// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Writable } from 'node:stream';
import { COMPONENTS, KitError } from '@arkenivajs/core';
import type { ManagedApiServer } from '@arkenivajs/api';
import { createTenantRoutingExample } from '../dist/main.js';
import type { TenantRoutingExampleOptions } from '../dist/main.js';

if (process.env.ARKENIVA_TENANT_EXAMPLE_DISPOSABLE !== '1' || !process.send)
  throw new Error('The child fixture requires an owned disposable IPC process');
let example: Awaited<ReturnType<typeof createTenantRoutingExample>> | undefined;
let stopping: Promise<void> | undefined;
const stop = () =>
  (stopping ??= (async () => {
    try {
      await example?.app.stop();
      process.exitCode = 0;
    } catch {
      process.exitCode = 1;
    } finally {
      if (process.connected) process.disconnect?.();
    }
  })());
process.once('SIGTERM', () => {
  void stop();
});
process.once('SIGINT', () => {
  void stop();
});
process.once('message', (message: TenantRoutingExampleOptions) => {
  void (async () => {
    try {
      if (message.service.environment !== 'test')
        throw new Error('The fixture is restricted to test configuration');
      example = await createTenantRoutingExample({
        ...message,
        destination: new Writable({
          write(_chunk, _encoding, done) {
            done();
          },
        }),
        eventExporter: {
          async export(events) {
            process.send?.({ type: 'events', events });
          },
        },
      });
      await example.app.start();
      process.send?.({
        type: 'ready',
        origin: example.app.resolve<ManagedApiServer>(COMPONENTS.api).address(),
        revision: example.service().api.revision(),
      });
    } catch (error) {
      const codes: string[] = [];
      let current: unknown = error;
      while (current instanceof KitError && codes.length < 8) {
        codes.push(current.code);
        current = current.cause;
      }
      process.send?.({ type: 'failed', codes });
      await stop();
      process.exitCode = 1;
    }
  })();
});
