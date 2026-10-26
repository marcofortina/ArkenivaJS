// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { Writable } from 'node:stream';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { Telemetry } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { createTelemetry } from '@arkenivajs/telemetry';
import { sessionsPlugin, SESSIONS_CAPABILITY } from '../../dist/index.js';
import type { SessionService } from '../../dist/index.js';
import { fixtureSettings } from './fixture.js';

test('Session observer failures cannot substitute authorization, hang calls or repeat credential writes', async () => {
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
      service: { name: 'sessions-observer-failure', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [
        loggingPlugin(),
        sessionsPlugin(f.settings),
        {
          id: 'sessions-test-observer',
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
      const sessions = app.resolve<SessionService>(SESSIONS_CAPABILITY),
        issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
      assert.equal((await sessions.validate(issued.value)).sessionId, issued.sessionId);
      assert.equal(writes, 1);
      f.state.primary = false;
      await assert.rejects(sessions.create(f.identity(), f.settings.defaultPolicy));
      assert.equal(writes, 1);
    } finally {
      await app.stop();
    }
  }
});

test('Session actual SDK exports fixed diagnostics while audit logs exclude credentials and account data', async () => {
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
  const service = { name: 'sessions-sdk-fixture', version: '1.0.0', environment: 'test' } as const;
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
        sessionsPlugin(f.settings),
        {
          id: 'sessions-sdk',
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
  const sessions = app.resolve<SessionService>(SESSIONS_CAPABILITY);
  try {
    const issued = await sessions.create(f.identity(), f.settings.defaultPolicy);
    await sessions.validate(issued.value);
    await assert.rejects(sessions.validate('missing'));
    const renewed = await sessions.renew(issued.value);
    await sessions.revoke(renewed.sessionId);
    await sessions.revokeAll(f.owner());
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
    for (const name of ['create', 'validate', 'renew', 'revoke', 'revoke_all']) {
      assert.ok(objects.some((value) => value.name === 'sessions.' + name));
      assert.ok(
        objects.some(
          (value) => value.name === 'sessions.' + name + '.duration' && value.unit === 'ms',
        ),
      );
      assert.ok(objects.some((value) => value.name === 'sessions.' + name + '.completed.ok'));
    }
    assert.ok(objects.some((value) => value.name === 'sessions.validate.completed.error'));
    assert.equal(telemetry.stats().droppedMetrics, 0);
    assert.equal(telemetry.stats().droppedSpans, 0);
    assert.equal(telemetry.stats().exportFailures, 0);
    assert.ok(lines.some((line) => line.includes('Session operation completed')));
    const serialized = JSON.stringify(bodies) + lines.join('');
    for (const secret of [
      issued.value,
      issued.sessionId,
      renewed.value,
      renewed.sessionId,
      f.owner().subject,
      f.owner().issuer,
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
    }
  }
});
