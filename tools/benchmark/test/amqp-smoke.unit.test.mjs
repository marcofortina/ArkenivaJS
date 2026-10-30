// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { amqpWorkload, amqpIterations, amqpWarmupIterations } from '../amqp-workload.mjs';

const fixture = {
  exchange: 'owned-helper-exchange',
  marker: 'owned-helper-private-body',
  smokeMessagePrefix: 'owned-helper-private-id',
};

test('AMQP smoke callbacks await a confirmed receipt and admit only one outstanding publication', async () => {
  let release,
    calls = 0,
    request;
  const service = {
    publish(input) {
      calls++;
      request = input;
      return new Promise((resolve) => {
        release = resolve;
      });
    },
  };
  const workload = amqpWorkload(service, fixture);
  let completed = false;
  const pending = workload.publishConfirmed().then((value) => {
    completed = true;
    return value;
  });
  assert.equal(completed, false);
  assert.equal(calls, 1);
  await assert.rejects(workload.publishConfirmed(), /sequential/);
  assert.equal(calls, 1);
  assert.equal(request.connection, 'events');
  assert.equal(request.exchange, fixture.exchange);
  assert.equal(request.routingKey, 'native');
  assert.equal(request.mandatory, true);
  assert.equal(request.persistent, false);
  assert.equal(request.body.length, 1024);
  assert.equal(request.body.subarray(0, fixture.marker.length).toString(), fixture.marker);
  assert.deepEqual(request.headers, { note: fixture.marker, sequence: 1, enabled: true });
  release({ messageId: request.messageId, status: 'confirmed' });
  assert.equal(await pending, 'confirmed');
  assert.equal(completed, true);
});

test('AMQP smoke rejects uncertain, unroutable, mismatched and failed receipts without replay', async () => {
  for (const outcome of ['unknown', 'unroutable', 'mismatch', 'error']) {
    let calls = 0;
    const service = {
      async publish(input) {
        calls++;
        if (outcome === 'error') throw new Error('The owned publisher failed');
        return {
          messageId: outcome === 'mismatch' ? 'another-owned-message' : input.messageId,
          status: outcome === 'mismatch' ? 'confirmed' : outcome,
        };
      },
    };
    await assert.rejects(amqpWorkload(service, fixture).publishConfirmed());
    assert.equal(calls, 1);
  }
});

test('AMQP smoke caps its queue-producing callbacks and gives every accepted publication a distinct identity', async () => {
  const identities = new Set();
  const service = {
    async publish(input) {
      assert.equal(identities.has(input.messageId), false);
      identities.add(input.messageId);
      return { messageId: input.messageId, status: 'confirmed' };
    },
  };
  const workload = amqpWorkload(service, fixture),
    expected = amqpIterations + amqpWarmupIterations;
  for (let index = 0; index < expected; index++) await workload.publishConfirmed();
  await assert.rejects(workload.publishConfirmed(), /bound is exceeded/);
  assert.equal(identities.size, expected);
});

test('AMQP smoke requires a disposable runner and full campaigns fail before fixture or report access', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-amqp-smoke-guard-')),
    script = fileURLToPath(new URL('../amqp.mjs', import.meta.url));
  try {
    const env = { ...process.env, ARKENIVA_AMQP_FIXTURE: join(directory, 'missing-fixture.json') };
    delete env.ARKENIVA_AMQP_BENCHMARK_DISPOSABLE;
    for (const mode of ['--smoke', '--full']) {
      const output = join(directory, mode.slice(2));
      const error = await promisify(execFile)(process.execPath, [script, mode, output], {
        env,
        timeout: 5000,
        maxBuffer: 65536,
      }).then(
        () => assert.fail('An unauthorized AMQP measurement was accepted'),
        (cause) => cause,
      );
      assert.match(
        error.stderr,
        mode === '--smoke' ? /explicitly disposable/ : /Use --verify or --smoke/,
      );
      await assert.rejects(access(output));
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
