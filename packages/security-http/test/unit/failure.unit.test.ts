// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { setImmediate } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { apiPlugin } from '@arkenivajs/api';
import { fixtureSettings, startFixture } from './fixture.js';
import { securityHttpPlugin } from '../../dist/index.js';
import { capture } from '../../dist/settings.js';

const rejected = (error: unknown) => error instanceof KitError;

test('Storage/HMAC/authority outages and key rotation cannot reuse a cached success or bypass CSRF', async () => {
  const f = await startFixture();
  try {
    const token = await f.as(f.alice.cookie, () =>
      f.service.csrfToken({ sessionId: f.alice.sessionId }),
    );
    const context = { sessionId: f.alice.sessionId, origin: 'https://app.fixture.invalid' };
    for (const name of ['storageAvailable', 'hmacAvailable', 'authorityAvailable'] as const) {
      f.state[name] = false;
      await assert.rejects(
        f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token)),
        rejected,
      );
      await assert.rejects(
        f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.alice.sessionId })),
        rejected,
      );
      f.state[name] = true;
      await f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token));
    }
    f.keys.current = randomBytes(32);
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.verifyCsrf(context, token)),
      rejected,
    );
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.alice.sessionId })),
      rejected,
    );
  } finally {
    await f.close();
  }
});

test('Expired, missing, corrupted and modified tokens remain fail-closed across separate application instances', async () => {
  const shared = fixtureSettings(),
    first = await startFixture(shared),
    second = await startFixture(shared);
  try {
    const token = await first.as(first.alice.cookie, () =>
      first.service.csrfToken({ sessionId: first.alice.sessionId }),
    );
    const context = { sessionId: first.alice.sessionId, origin: 'https://app.fixture.invalid' };
    await second.as(second.alice.cookie, () => second.service.verifyCsrf(context, token));
    await first.close();
    await second.as(second.alice.cookie, () => second.service.verifyCsrf(context, token));
    for (const bad of [
      '',
      'v0.' + token.slice(3),
      token + 'x',
      'v1.a.b',
      'v1.' + '_'.repeat(43) + '.a',
    ])
      await assert.rejects(
        second.as(second.alice.cookie, () => second.service.verifyCsrf(context, bad)),
        rejected,
      );
    const [id, value] = [...shared.rows][0]!;
    shared.rows.set(id, { ...value, expiresAt: new Date(Date.now() - 1).toISOString() });
    await assert.rejects(
      second.as(second.alice.cookie, () => second.service.verifyCsrf(context, token)),
      rejected,
    );
    shared.rows.set(id, { ...value, binding: 'corrupted' });
    await assert.rejects(
      second.as(second.alice.cookie, () => second.service.verifyCsrf(context, token)),
      rejected,
    );
    shared.rows.clear();
    await assert.rejects(
      second.as(second.alice.cookie, () => second.service.verifyCsrf(context, token)),
      rejected,
    );
  } finally {
    try {
      await first.close();
    } finally {
      await second.close();
    }
  }
});

test('Aborted durable issuance retains bounded reservations until actual writes settle and never releases a token late', async () => {
  const f = await startFixture();
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    f.state.holdWrite = held;
    const controllers = Array.from({ length: 16 }, () => new AbortController());
    const calls = controllers.map((controller) =>
      f.as(f.alice.cookie, () =>
        f.service.csrfToken({ sessionId: f.alice.sessionId }, { signal: controller.signal }),
      ),
    );
    const deadline = performance.now() + 1000;
    while (f.state.authorizations < 16) {
      assert.ok(performance.now() < deadline);
      await setImmediate();
    }
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.alice.sessionId })),
      (error) => error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE',
    );
    const outcomes = calls.map((call) =>
      assert.rejects(call, (error) => error instanceof KitError && error.code === 'EK_ABORTED'),
    );
    for (const controller of controllers) controller.abort();
    await Promise.all(outcomes);
    await assert.rejects(
      f.as(f.alice.cookie, () => f.service.csrfToken({ sessionId: f.alice.sessionId })),
      (error) => error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE',
    );
    release();
    f.state.holdWrite = undefined;
    while (f.state.writes < 16) {
      assert.ok(performance.now() < deadline + 1000);
      await setImmediate();
    }
    await setImmediate();
    assert.equal(
      typeof (await f.as(f.alice.cookie, () =>
        f.service.csrfToken({ sessionId: f.alice.sessionId }),
      )),
      'string',
    );
  } finally {
    release();
    await f.close();
  }
});

test('Invalid timeouts, structural signals and manually added identity/request properties fail before authority access', async () => {
  const f = await startFixture();
  try {
    for (const timeoutMs of [0, -1, 1.1, Infinity, NaN, 1001])
      await assert.rejects(
        f.as(f.alice.cookie, () =>
          f.service.csrfToken({ sessionId: f.alice.sessionId }, { timeoutMs }),
        ),
        rejected,
      );
    await assert.rejects(
      f.service.csrfToken(
        { sessionId: f.alice.sessionId },
        { signal: { aborted: false } as AbortSignal },
      ),
      rejected,
    );
    await assert.rejects(
      f.service.csrfToken({
        sessionId: f.alice.sessionId,
        request: { cookies: { '__Host-session': f.alice.cookie } },
      } as never),
      rejected,
    );
    assert.equal(f.state.authorizations, 0);
    await f.close();
    assert.throws(() => f.service.getEffectivePolicy(), rejected);
    assert.throws(() => f.service.installHeaders(f.settings.policy), rejected);
    await assert.rejects(f.service.csrfToken({ sessionId: f.alice.sessionId }), rejected);
  } finally {
    await f.close();
  }
});

test('Production rejects test-only storage and providers before a listener becomes ready', async () => {
  const f = fixtureSettings();
  const app = await createApplication({
    service: { name: 'http-security-production', version: '1.0.0', environment: 'production' },
    logging: { level: 'info' },
    plugins: [loggingPlugin(), apiPlugin(), securityHttpPlugin(f.settings)],
  });
  try {
    await assert.rejects(app.start(), rejected);
  } finally {
    await app.stop().catch(() => undefined);
  }
  const tagged = {
    ...f.settings,
    csrfStore: { ...f.settings.csrfStore, securityLevel: 'production' as const },
  };
  assert.equal(capture(tagged).productionUnsafe, true);
});

test('Configured proxy peers are exact CIDR matches and malformed/sparse/getter configuration cannot broaden trust', () => {
  const f = fixtureSettings();
  const settings = capture({ ...f.settings, trustedProxyCidrs: ['127.0.0.1/32', '::1/128'] });
  assert.equal(settings.permitsProxy('127.0.0.1'), true);
  assert.equal(settings.permitsProxy('127.0.0.2'), false);
  assert.equal(settings.permitsProxy('::1'), true);
  assert.equal(settings.permitsProxy('invalid'), false);
  for (const value of [null, ['127.0.0.1'], ['127.0.0.1/33'], ['::1/129'], new Array(1)])
    assert.throws(
      () => securityHttpPlugin({ ...f.settings, trustedProxyCidrs: value } as never),
      rejected,
    );
  let reads = 0;
  const unsafe = Object.defineProperty({ ...f.settings }, 'authority', {
    get() {
      reads++;
      return f.settings.authority;
    },
  });
  assert.throws(() => securityHttpPlugin(unsafe), rejected);
  assert.equal(reads, 0);
});
