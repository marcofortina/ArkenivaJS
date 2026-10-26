// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { Writable } from 'node:stream';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { Telemetry } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { createTelemetry } from '@arkenivajs/telemetry';
import { passwordPlugin, PASSWORD_CAPABILITY } from '../../dist/index.js';
import type { PasswordService } from '../../dist/index.js';
import { fixtureSettings } from './fixture.js';

test('Password observer failures cannot substitute authorization, hang calls or repeat credential writes', async () => {
  for (const behavior of ['throw', 'substitute', 'repeat', 'hang'] as const) {
    const f = fixtureSettings(),
      commit = f.store.atomicBatch.bind(f.store);
    let writes = 0;
    f.store.atomicBatch = async (...args) => {
      writes++;
      return commit(...args);
    };
    const observer: Telemetry = {
      async measure(_name, work) {
        return work();
      },
      withSpan<T>(_name: string, work: () => Promise<T> | T): Promise<T> {
        if (behavior === 'throw') throw new Error('Private observer failure');
        if (behavior === 'substitute') return Promise.resolve({ forged: true } as T);
        if (behavior === 'hang') return new Promise<T>(() => undefined);
        const result = Promise.resolve(work());
        void Promise.resolve(work()).catch(() => undefined);
        return result;
      },
      addCounter() {
        throw new Error('Private observer failure');
      },
      recordHistogram() {
        throw new Error('Private observer failure');
      },
      setGauge() {},
      async flush() {},
    };
    const app = await createApplication({
      service: { name: 'password-observer-failure', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [
        loggingPlugin(),
        passwordPlugin(f.settings),
        {
          id: 'password-test-observer',
          version: '1.0.0',
          capabilities: new Set(['telemetry']),
          init(context) {
            context.provide(COMPONENTS.telemetry, observer);
          },
          close() {},
        },
      ],
    });
    try {
      await app.start();
      const passwords = app.resolve<PasswordService>(PASSWORD_CAPABILITY),
        issued = await passwords.createReset(f.owner(), f.owner());
      await passwords.consumeReset(issued.value, randomBytes(24).toString('base64url'));
      assert.equal(f.credentials.size, 1);
      assert.equal(writes, 1);
      f.state.primary = false;
      await assert.rejects(passwords.createReset(f.owner(), f.owner()));
      assert.equal(writes, 1);
    } finally {
      await app.stop();
      f.close();
    }
  }
});

test('Password actual SDK exports fixed diagnostics while audit logs exclude credentials and account data', async () => {
  const bodies: unknown[] = [],
    lines: string[] = [];
  let total = 0;
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(String(chunk));
      callback();
    },
  });
  const receiver = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 4194304) request.destroy();
      else chunks.push(chunk);
    });
    request.on('end', () => {
      bodies.push(JSON.parse(Buffer.concat(chunks).toString()) as unknown);
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{}');
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  const address = receiver.address();
  assert.ok(address && typeof address !== 'string');
  const service = { name: 'password-sdk-fixture', version: '1.0.0', environment: 'test' } as const;
  const telemetry = createTelemetry({
    service,
    mode: 'detailed',
    samplingRatio: 1,
    endpoint: 'http://127.0.0.1:' + address.port,
    allowInsecureLoopback: true,
    exportIntervalMs: 1000,
    exportTimeoutMs: 1000,
  });
  const f = fixtureSettings(),
    app = await createApplication({
      service,
      logging: { level: 'info' },
      plugins: [
        loggingPlugin({ destination }),
        passwordPlugin(f.settings),
        {
          id: 'password-sdk',
          version: '1.0.0',
          capabilities: new Set(['telemetry']),
          init(context) {
            context.provide(COMPONENTS.telemetry, telemetry);
          },
          close() {},
        },
      ],
    });
  await app.start();
  const passwords = app.resolve<PasswordService>(PASSWORD_CAPABILITY);
  try {
    const plain = 'Unicode e\u0301 ' + randomBytes(24).toString('base64url'),
      next = randomBytes(24).toString('base64url'),
      hash = await passwords.hash(plain),
      reset = await passwords.createReset(f.owner(), f.owner());
    await passwords.verify(plain, hash);
    await passwords.verify(next, hash);
    await passwords.consumeReset(reset.value, next);
    await assert.rejects(passwords.consumeReset(reset.value, plain));
    await telemetry.flush();
    const objects: Record<string, unknown>[] = [];
    const visit = (value: unknown): void => {
      if (!value || typeof value !== 'object') return;
      if (Array.isArray(value)) {
        value.forEach(visit);
        return;
      }
      objects.push(value as Record<string, unknown>);
      Object.values(value).forEach(visit);
    };
    bodies.forEach(visit);
    for (const name of ['hash', 'verify', 'create_reset', 'consume_reset']) {
      assert.ok(objects.some((value) => value.name === 'password.' + name));
      assert.ok(
        objects.some(
          (value) => value.name === 'password.' + name + '.duration' && value.unit === 'ms',
        ),
      );
      assert.ok(objects.some((value) => value.name === 'password.' + name + '.completed.ok'));
    }
    assert.ok(objects.some((value) => value.name === 'password.consume_reset.completed.error'));
    assert.ok(objects.some((value) => value.name === 'password.verify.result.accepted'));
    assert.ok(objects.some((value) => value.name === 'password.verify.result.denied'));
    assert.equal(telemetry.stats().droppedMetrics, 0);
    assert.equal(telemetry.stats().droppedSpans, 0);
    assert.equal(telemetry.stats().exportFailures, 0);
    assert.ok(lines.some((line) => line.includes('Password operation completed')));
    const serialized = JSON.stringify(bodies) + lines.join('');
    for (const secret of [
      plain,
      next,
      hash.phc,
      reset.value,
      reset.requestId,
      f.owner().subject,
      f.owner().issuer,
      ...[...f.credentials.values()].map((value) => value.phc),
      ...[...f.rows.values()].filter((row) => row.digest).map((row) => String(row.digest)),
    ])
      assert.equal(serialized.includes(secret), false);
  } finally {
    try {
      await app.stop();
      await telemetry.close();
    } finally {
      receiver.closeAllConnections();
      await new Promise<void>((resolve) => receiver.close(() => resolve()));
      destination.end();
      f.close();
    }
  }
});
