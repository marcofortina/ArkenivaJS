// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';

/** Validate retained measurements from actual reports, including their declared time unit. */
export function assertRawLatencySamples(record) {
  assert.equal(record.rawLatency?.unit, 'milliseconds');
  const values = record.rawLatency.values;
  assert.ok(Array.isArray(values));
  assert.equal(values.length, record.sampleCount);
  assert.ok(values.length > 0 && values.length <= 10000);
  assert.ok(values.every((value) => Number.isFinite(value) && value >= 0));
  const minimum = Math.min(...values) * 1e6,
    maximum = Math.max(...values) * 1e6;
  for (const value of Object.values(record.latencyNanoseconds))
    assert.ok(
      value >= minimum && value <= maximum,
      'Reported quantiles must fit the retained millisecond samples',
    );
}
