// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { Writable } from 'node:stream';
import test from 'node:test';
import { runObservabilityExample } from '../../src/main.js';

test('Observability guide emits safe contextual JSON and actual process measurements', async () => {
  const lines: string[] = [];
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(String(chunk));
      callback();
    },
  });
  const snapshot = await runObservabilityExample(destination);
  assert.equal(destination.destroyed, false);
  assert.equal(lines.length, 2);
  const warning = JSON.parse(lines[0]!);
  assert.equal(warning.level, 40);
  assert.equal(warning.service, 'observability-example');
  assert.equal(warning.requestId, 'example-request');
  assert.equal(warning.credentials.password, '[REDACTED]');
  assert.deepEqual(Object.keys(warning.error).sort(), ['code', 'message']);
  assert.ok(!lines.join('').includes('fake-example-'));
  assert.ok(!lines.join('').includes('Private native cause'));
  assert.equal(snapshot.processId, process.pid);
  assert.ok(snapshot.memoryRssBytes > 0);
  assert.ok(snapshot.cpuUserMicros >= 0);
  assert.deepEqual(JSON.parse(lines[1]!).snapshot, snapshot);
  destination.destroy();
});

test('The documented observability CLI emits two JSON lines and exits after cleanup', () => {
  const output = execFileSync(process.execPath, ['dist/main.js'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    timeout: 5000,
  });
  const lines = output
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line));
  assert.equal(lines.length, 2);
  assert.equal(lines[0].credentials.password, '[REDACTED]');
  assert.ok(lines[1].snapshot.processId > 0);
  assert.ok(lines[1].snapshot.memoryRssBytes > 0);
});
