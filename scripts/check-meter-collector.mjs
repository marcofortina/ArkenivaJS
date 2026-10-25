// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const evidence = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const records = readFileSync(process.argv[3], 'utf8')
  .trim()
  .split('\n')
  .filter(Boolean)
  .map((line) => JSON.parse(line));
const selected = records.filter((event) => event.operation === evidence.operation);
assert.equal(selected.length, 2);
assert.deepEqual(selected.map((event) => event.eventId).sort(), [...evidence.eventIds].sort());
assert.deepEqual(selected.map((event) => event.tenantId).sort(), evidence.tenantIds);
assert.equal(new Set(selected.map((event) => event.eventId)).size, 2);
for (const event of selected) {
  assert.equal(event.schemaVersion, '1.0.0');
  assert.equal(event.status, 'ok');
  assert.deepEqual(event.counters['db.query'], {
    unit: 'operations',
    source: 'observed',
    value: 2,
  });
  assert.equal(event.quality.complete, true);
  assert.ok(event.startedAt <= event.endedAt);
}
assert.ok(!JSON.stringify(selected).includes('Bearer '));
console.log(
  'Durable collector records contain both unique tenant events despite duplicate delivery',
);
