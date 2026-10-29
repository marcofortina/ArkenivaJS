// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { failure } from './policy.js';

/** Rearm long configured deadlines without Node's overflowing-delay one-millisecond fallback. */
export function subscriptionTimer(durationMs: number, work: () => void): () => void {
  if (!Number.isSafeInteger(durationMs) || durationMs < 1) throw failure();
  const deadline = performance.now() + durationMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cancelled = false;
  const arm = () => {
    if (cancelled) return;
    const remaining = Math.ceil(deadline - performance.now());
    if (remaining <= 0) {
      cancelled = true;
      work();
      return;
    }
    timer = setTimeout(arm, Math.min(remaining, 2147483647));
    timer.unref();
  };
  timer = setTimeout(arm, Math.min(durationMs, 2147483647));
  timer.unref();
  return () => {
    cancelled = true;
    clearTimeout(timer);
  };
}
