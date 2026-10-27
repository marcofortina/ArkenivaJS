// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Settings } from './settings.js';
import { failure } from './validation.js';

/** Initialized before the consumer so rollback owns even an uncooperative initial key lookup. */
export function providerTask(settings: Settings, owner: AbortSignal) {
  const controller = new AbortController(),
    signal = AbortSignal.any([owner, controller.signal]);
  let task: Promise<string> | undefined,
    closed = false;
  return {
    load(): Promise<string> {
      if (closed || signal.aborted) return Promise.reject(failure('EK_ABORTED'));
      if (!task) {
        task = Promise.resolve().then(() => {
          if (signal.aborted) throw failure('EK_ABORTED');
          return settings.hmac.digest(
            'arkenivajs.security-http.native-key.v1',
            [],
            settings.keyRef,
            { signal, timeoutMs: settings.timeoutMs },
          );
        });
        void task.catch(() => undefined);
      }
      return task;
    },
    async close() {
      closed = true;
      controller.abort();
      await task?.catch(() => undefined);
    },
  };
}
export type ProviderTask = ReturnType<typeof providerTask>;
