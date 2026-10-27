// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { Logger, Telemetry } from '@arkenivajs/core';
import { fixtureSettings, startFixture } from './fixture.js';
import { observation } from '../../dist/observation.js';

test('Actual OpenTelemetry SDK and Pino observe CSRF rejection without token, cookie, key or session labels', async () => {
  const bodies: string[] = [];
  const server = createServer((request, response) => {
    void (async () => {
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        if (bytes > 1048576) throw new Error('Owned collector request overflow');
        chunks.push(chunk);
      }
      bodies.push(Buffer.concat(chunks).toString('utf8'));
      response.setHeader('content-type', 'application/json');
      response.end('{}');
    })().catch(() => {
      response.statusCode = 500;
      response.end('{}');
    });
  });
  let f: Awaited<ReturnType<typeof startFixture>> | undefined;
  try {
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Owned collector is unavailable');
    f = await startFixture(fixtureSettings(), undefined, 'http://127.0.0.1:' + address.port);
    const token = await f.as(f.alice.cookie, () =>
      f!.service.csrfToken({ sessionId: f!.alice.sessionId }),
    );
    await assert.rejects(f.service.csrfToken({ sessionId: f.alice.sessionId }));
    const response = await fetch(f.origin + '/protected', { method: 'POST' });
    assert.equal(response.status, 403);
    await response.arrayBuffer();
    await f.app.telemetry.flush();
    const exported = bodies.join('');
    assert.match(exported, /security.http.csrf.rejections/);
    assert.match(exported, /security.http.duration.ms/);
    const all = exported + f.logs.join('');
    for (const secret of [
      token,
      token.split('.')[1]!,
      f.alice.cookie,
      f.alice.sessionId,
      f.keys.current.toString('hex'),
    ])
      assert.equal(all.includes(secret), false);
  } finally {
    try {
      await f?.close();
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }
});

test('Observer exceptions cannot replace success, suppress rejection or replay the protected work', async () => {
  let calls = 0;
  const observers = observation({
    logger: {
      debug() {
        throw new Error('Private observer failure');
      },
    } as unknown as Logger,
  });
  assert.equal(
    await observers.run('issue', async () => {
      calls++;
      return 'accepted';
    }),
    'accepted',
  );
  const rejection = new Error('Expected denial');
  await assert.rejects(
    observers.run('verify', async () => {
      calls++;
      throw rejection;
    }),
    (error) => error === rejection,
  );
  const failedMetric = observation({
    telemetry: {
      addCounter() {
        throw new Error('Private metric failure');
      },
    } as unknown as Telemetry,
  });
  assert.doesNotThrow(() => failedMetric.reject());
  assert.equal(calls, 2);
});
