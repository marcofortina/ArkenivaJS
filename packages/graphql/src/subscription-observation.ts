// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncResource } from 'node:async_hooks';
import type { Telemetry } from '@arkenivajs/core';
import type { Operation } from './operation.js';
import { traceOperation } from './observation.js';

/** Keep each authenticated source/event span attached through physical scope retirement. */
export async function traceSubscriptionScope(
  telemetry: Telemetry | undefined,
  parent: AsyncResource | undefined,
  scope: Operation,
): Promise<void> {
  if (!telemetry) return;
  let ready!: () => void;
  const captured = new Promise<void>((resolve) => {
    ready = resolve;
  });
  let lifetime: Promise<void> | undefined;
  const capture = () =>
    (lifetime ??= (async () => {
      const resource = new AsyncResource('GraphqlSubscriptionScope');
      scope.runInContext = (work) => resource.runInAsyncScope(work);
      ready();
      await scope.completion;
      scope.runInContext = undefined;
      resource.emitDestroy();
    })());
  const start = () => traceOperation({ telemetry, detailed: false }, 'subscription', capture);
  // The existing instrumentation helper invokes capture once even when diagnostics throw.
  const pending = parent ? parent.runInAsyncScope(start) : start();
  void pending.catch(() => ready());
  // A provider that never invokes its continuation cannot hold authenticated work indefinitely.
  queueMicrotask(() => {
    if (!lifetime) void (parent ? parent.runInAsyncScope(capture) : capture());
  });
  await captured;
}
