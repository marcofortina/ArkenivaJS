// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';

export const diagnosticsSettings = Object.freeze({
  eventLoopUtilization: true,
  eventLoopDelay: false,
});

/** Bare process measurements use the same native sources and interval semantics. */
export function nativeDiagnostics() {
  let previous = performance.eventLoopUtilization(),
    closed = false;
  return {
    snapshot() {
      assert.equal(closed, false, 'The native collector is closed');
      const cpu = process.cpuUsage(),
        memory = process.memoryUsage(),
        current = performance.eventLoopUtilization(),
        delta = performance.eventLoopUtilization(current, previous);
      previous = current;
      return Object.freeze({
        timestamp: new Date().toISOString(),
        processId: process.pid,
        cpuUserMicros: cpu.user,
        cpuSystemMicros: cpu.system,
        memoryRssBytes: memory.rss,
        heapUsedBytes: memory.heapUsed,
        ...(delta.active + delta.idle > 0 && Number.isFinite(delta.utilization)
          ? { eventLoopUtilization: delta.utilization }
          : {}),
      });
    },
    close() {
      closed = true;
    },
  };
}

export function verifyDiagnostics(service) {
  for (let index = 0; index < 20; index++) {
    const started = Date.now(),
      before = process.cpuUsage(),
      snapshot = service.snapshot(),
      after = process.cpuUsage(),
      ended = Date.now();
    assert.equal(snapshot.processId, process.pid);
    assert.equal(Object.isFrozen(snapshot), true);
    assert.ok(snapshot.timestamp.endsWith('Z'));
    assert.ok(Date.parse(snapshot.timestamp) >= started && Date.parse(snapshot.timestamp) <= ended);
    assert.ok(Number.isSafeInteger(snapshot.cpuUserMicros));
    assert.ok(Number.isSafeInteger(snapshot.cpuSystemMicros));
    assert.ok(snapshot.cpuUserMicros >= before.user && snapshot.cpuUserMicros <= after.user);
    assert.ok(
      snapshot.cpuSystemMicros >= before.system && snapshot.cpuSystemMicros <= after.system,
    );
    assert.ok(Number.isSafeInteger(snapshot.memoryRssBytes) && snapshot.memoryRssBytes > 0);
    assert.ok(Number.isSafeInteger(snapshot.heapUsedBytes) && snapshot.heapUsedBytes > 0);
    assert.equal(snapshot.eventLoopDelayP99Ms, undefined);
    assert.ok(
      snapshot.eventLoopUtilization === undefined ||
        (Number.isFinite(snapshot.eventLoopUtilization) &&
          snapshot.eventLoopUtilization >= 0 &&
          snapshot.eventLoopUtilization <= 1),
    );
  }
  return { checkedSnapshots: 20, nativeCpuBoundsVerified: true, processScopeOnly: true };
}

export function diagnosticsWorkload(service) {
  return { snapshot: () => service.snapshot() };
}
