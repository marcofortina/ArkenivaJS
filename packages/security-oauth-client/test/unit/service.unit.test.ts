// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture } from './fixture.js';
import { KitError } from '@arkenivajs/core';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createServer } from 'node:http';
import { runtime, captureSettings } from '../../dist/runtime.js';
import { oauthClientPlugin } from '../../dist/index.js';

test(
  'OAuth actual SDK exchanges signed PKCE grants, preserves exact redirect queries and rotates encrypted refresh references',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const start = await f.first.oauth.beginAuthorization({
          subject: f.owner(),
          audience: f.server.audience,
          scopes: ['openid', 'orders.read'],
          returnPath: '/orders',
        }),
        url = new URL(start.authorizationUrl);
      assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
      assert.equal(url.searchParams.get('response_type'), 'code');
      const callback = await f.server.authorize(start.authorizationUrl),
        grant = await f.second.oauth.exchangeCode(callback);
      assert.equal(grant.tokenType, 'Bearer');
      assert.ok(grant.refreshRef);
      assert.equal('identity' in grant, false);
      assert.equal('assurance' in grant, false);
      const next = await f.first.oauth.refresh(grant.refreshRef);
      assert.ok(next.refreshRef);
      assert.notEqual(next.refreshRef, grant.refreshRef);
      const serialized = JSON.stringify([...f.memory.rows.values()]);
      for (const sensitive of [
        grant.accessToken,
        next.accessToken,
        start.stateRef.split('.')[2]!,
        grant.refreshRef.split('.')[3]!,
        f.server.secret,
        url.searchParams.get('nonce')!,
      ])
        assert.equal(serialized.includes(sensitive), false);
      await f.second.oauth.revoke(next.refreshRef);
      await assert.rejects(f.first.oauth.refresh(next.refreshRef));
      assert.ok(f.server.counts.jwks > 0);
      assert.ok(f.server.counts.revoke > 0);
    } finally {
      await f.close();
    }
  },
);

const rejected = (code: string) => (error: unknown) =>
  error instanceof KitError && error.code === code;
const begin = async (f: Awaited<ReturnType<typeof fixture>>) => {
  const start = await f.first.oauth.beginAuthorization({
    audience: f.server.audience,
    scopes: ['openid', 'orders.read'],
    returnPath: '/orders',
  });
  return { start, callback: await f.server.authorize(start.authorizationUrl) };
};
test('OAuth ciphertext modification fails authenticated decryption before any token request', async () => {
  const f = await fixture();
  try {
    const { callback } = await begin(f),
      item = [...f.memory.rows].find(([, row]) => row.kind === 'authorization')!;
    const sealed = item[1].sealed as Readonly<{ ciphertext: string }>;
    f.memory.rows.set(item[0], {
      ...item[1],
      sealed: {
        ...sealed,
        ciphertext: (sealed.ciphertext[0] === 'A' ? 'B' : 'A') + sealed.ciphertext.slice(1),
      },
    });
    await assert.rejects(f.second.oauth.exchangeCode(callback), rejected('EK_OAUTH_STATE'));
    assert.equal(f.server.counts.token, 0);
  } finally {
    await f.close();
  }
});
test('OAuth unsupported provider operations retain explicit capability metadata and fail closed locally', async () => {
  const f = await fixture();
  try {
    f.server.mode.noAuthorization = true;
    const limited = await f.instance();
    await assert.rejects(
      limited.oauth.beginAuthorization({
        audience: f.server.audience,
        scopes: ['openid', 'orders.read'],
        returnPath: '/orders',
      }),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_UNSUPPORTED_CAPABILITY' &&
        error.details?.capability === 'authorization_code' &&
        error.details.supported === false,
    );
    f.server.mode.noAuthorization = false;
    f.server.mode.noRevocation = true;
    const noRevoke = await f.instance();
    const start = await noRevoke.oauth.beginAuthorization({
        audience: f.server.audience,
        scopes: ['openid', 'orders.read'],
        returnPath: '/orders',
      }),
      grant = await noRevoke.oauth.exchangeCode(await f.server.authorize(start.authorizationUrl));
    await assert.rejects(
      noRevoke.oauth.revoke(grant.refreshRef!),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_UNSUPPORTED_CAPABILITY' &&
        error.details?.capability === 'token_revocation' &&
        error.details.supported === false,
    );
    await assert.rejects(noRevoke.oauth.refresh(grant.refreshRef!), rejected('EK_OAUTH_STATE'));
  } finally {
    await f.close();
  }
});
test('OAuth rejects invalid signed nonce, issuer, audience, expiry and signature without issuing a grant', async () => {
  const f = await fixture();
  try {
    for (const mode of [
      'badNonce',
      'badSignature',
      'wrongIssuer',
      'wrongAudience',
      'expiredIdToken',
    ] as const) {
      const { callback } = await begin(f);
      f.server.mode[mode] = true;
      await assert.rejects(f.first.oauth.exchangeCode(callback), rejected('EK_OAUTH_EXCHANGE'));
      f.server.mode[mode] = false;
      await assert.rejects(f.second.oauth.exchangeCode(callback), rejected('EK_OAUTH_STATE'));
    }
  } finally {
    await f.close();
  }
});
test('OAuth enforces scopes, audience, exact local return paths and runtime authorization before requesting tokens', async () => {
  const f = await fixture();
  try {
    for (const returnPath of [
      '//foreign.invalid',
      '/\\foreign.invalid',
      'https://foreign.invalid',
      '/orders\n',
    ])
      await assert.rejects(
        f.first.oauth.beginAuthorization({
          audience: f.server.audience,
          scopes: ['orders.read'],
          returnPath,
        }),
      );
    await assert.rejects(
      f.first.oauth.clientCredentials('https://foreign.invalid', ['orders.read']),
    );
    await assert.rejects(f.first.oauth.clientCredentials(f.server.audience, ['admin']));
    await assert.rejects(
      f.first.oauth.beginAuthorization({
        subject: { ...f.owner(), subject: 'forged' },
        audience: f.server.audience,
        scopes: ['orders.read'],
        returnPath: '/orders',
      }),
    );
    f.state.enabled = false;
    await assert.rejects(f.first.oauth.clientCredentials(f.server.audience, ['orders.read']));
    await assert.rejects(
      f.first.oauth.beginAuthorization({
        subject: f.owner(),
        audience: f.server.audience,
        scopes: ['orders.read'],
        returnPath: '/orders',
      }),
    );
    assert.equal(f.server.counts.token, 0);
  } finally {
    await f.close();
  }
});
test('OAuth real Pino and OpenTelemetry SDK exports preserve millisecond units without grant or owner data', async () => {
  const f = await fixture(true);
  const sensitive: string[] = [];
  try {
    const { start, callback } = await begin(f),
      grant = await f.first.oauth.exchangeCode(callback),
      next = await f.second.oauth.refresh(grant.refreshRef!);
    sensitive.push(
      grant.accessToken,
      grant.refreshRef!,
      next.accessToken,
      next.refreshRef!,
      f.server.secret,
      f.owner().subject,
      f.owner().issuer,
      start.stateRef,
      new URL(start.authorizationUrl).searchParams.get('nonce')!,
    );
  } finally {
    await f.close();
  }
  const diagnostics = [...f.logs, ...f.server.metricExports, ...f.server.traceExports].join('\n');
  assert.ok(f.server.traceExports.length > 0);
  for (const value of sensitive) assert.equal(diagnostics.includes(value), false);
  const metrics: { name: string; unit: string }[] = [];
  for (const raw of f.server.metricExports) {
    const envelope = JSON.parse(raw) as {
      resourceMetrics?: { scopeMetrics?: { metrics?: { name: string; unit: string }[] }[] }[];
    };
    for (const resource of envelope.resourceMetrics ?? [])
      for (const scope of resource.scopeMetrics ?? []) metrics.push(...(scope.metrics ?? []));
  }
  for (const name of [
    'oauth.begin_authorization.duration',
    'oauth.exchange_code.duration',
    'oauth.refresh.duration',
  ])
    assert.ok(metrics.some((metric) => metric.name === name && metric.unit === 'ms'));
});
test('OAuth does not expose grants for provider outage, changed scope, unsupported token type or invalid lifetime', async () => {
  const f = await fixture();
  try {
    for (const mode of ['unavailable', 'wrongScope', 'wrongTokenType', 'invalidExpiry'] as const) {
      f.server.mode[mode] = true;
      await assert.rejects(f.first.oauth.clientCredentials(f.server.audience, ['orders.read']));
      f.server.mode[mode] = false;
    }
    f.server.mode.oversizedResponse = true;
    await assert.rejects(f.first.oauth.clientCredentials(f.server.audience, ['orders.read']));
  } finally {
    await f.close();
  }
});
test('OAuth state and refresh records cannot cross the trusted tenant or survive unauthorized mutation', async () => {
  const f = await fixture();
  try {
    f.state.tenant = 'tenant-a';
    const { callback } = await begin(f);
    f.state.tenant = 'tenant-b';
    await assert.rejects(f.second.oauth.exchangeCode(callback));
    f.state.tenant = 'tenant-a';
    const grant = await f.first.oauth.exchangeCode(callback);
    f.state.tenant = 'tenant-b';
    await assert.rejects(f.second.oauth.refresh(grant.refreshRef!));
    await assert.rejects(f.second.oauth.revoke(grant.refreshRef!));
    f.state.tenant = 'tenant-a';
    const row = [...f.memory.rows].find(([, value]) => value.kind === 'refresh')!;
    f.memory.rows.set(row[0], { ...row[1], audience: 'https://foreign.fixture.invalid' });
    await assert.rejects(f.first.oauth.refresh(grant.refreshRef!));
    assert.equal(f.server.counts.refresh, 0);
  } finally {
    await f.close();
  }
});
test('OAuth unknown and forged refresh proofs cannot revoke a legitimate family', async () => {
  const f = await fixture();
  try {
    const { callback } = await begin(f),
      grant = await f.first.oauth.exchangeCode(callback),
      parts = grant.refreshRef!.split('.');
    parts[3] = randomBytes(32).toString('base64url');
    await assert.rejects(f.second.oauth.refresh(parts.join('.')));
    await assert.rejects(f.second.oauth.revoke(parts.join('.')));
    assert.ok((await f.first.oauth.refresh(grant.refreshRef!)).refreshRef);
    assert.equal(f.server.counts.revoke, 0);
  } finally {
    await f.close();
  }
});
test('OAuth refuses a nonrotating refresh response and closes the compromised family', async () => {
  const f = await fixture();
  try {
    const { callback } = await begin(f),
      grant = await f.first.oauth.exchangeCode(callback);
    f.server.mode.noRotation = true;
    await assert.rejects(f.second.oauth.refresh(grant.refreshRef!), rejected('EK_OAUTH_POLICY'));
    f.server.mode.noRotation = false;
    await assert.rejects(f.first.oauth.refresh(grant.refreshRef!));
    assert.equal(f.server.counts.refresh, 1);
    assert.equal(f.server.counts.revoke, 1);
  } finally {
    await f.close();
  }
});
test('OAuth rejects stale state and unavailable durable storage without a token exchange', async () => {
  const f = await fixture();
  try {
    const { callback } = await begin(f),
      entry = [...f.memory.rows].find(([, row]) => row.kind === 'authorization')!;
    f.memory.rows.set(entry[0], { ...entry[1], expiresAt: new Date(0).toISOString() });
    await assert.rejects(f.first.oauth.exchangeCode(callback));
    f.memory.state.storeAvailable = false;
    await assert.rejects(f.first.oauth.clientCredentials(f.server.audience, ['orders.read']));
    assert.equal(f.server.counts.token, 0);
  } finally {
    await f.close();
  }
});
test('OAuth bootstrap rejects untrusted metadata endpoints and PKCE downgrade', async () => {
  const f = await fixture();
  try {
    f.server.mode.foreignEndpoint = true;
    await assert.rejects(f.instance());
    f.server.mode.foreignEndpoint = false;
    f.server.mode.noPkce = true;
    await assert.rejects(f.instance());
  } finally {
    await f.close();
  }
});
test('OAuth token endpoint redirects do not forward client credentials or follow the foreign location', async () => {
  const f = await fixture();
  let requests = 0;
  const trap = createServer((_request, response) => {
    requests++;
    response.end('{}');
  });
  await new Promise<void>((resolve) => trap.listen(0, '127.0.0.1', resolve));
  try {
    const address = trap.address();
    assert.ok(address && typeof address !== 'string');
    f.server.mode.tokenRedirect = 'http://127.0.0.1:' + address.port + '/token';
    await assert.rejects(f.first.oauth.clientCredentials(f.server.audience, ['orders.read']));
    assert.equal(requests, 0);
    assert.equal(f.server.counts.token, 1);
  } finally {
    trap.closeAllConnections();
    await new Promise<void>((resolve) => trap.close(() => resolve()));
    await f.close();
  }
});
test('OAuth cancellation reports an unknown provider outcome and never retries token requests', async () => {
  const f = await fixture();
  let release!: () => void;
  f.server.mode.holdToken = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    const controller = new AbortController(),
      pending = f.first.oauth.clientCredentials(f.server.audience, ['orders.read'], {
        signal: controller.signal,
      });
    void pending.catch(() => undefined);
    for (let i = 0; f.server.counts.token === 0 && i < 100; i++) await delay(10);
    assert.equal(f.server.counts.token, 1);
    controller.abort();
    await assert.rejects(
      pending,
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_ABORTED' &&
        error.details?.outcome === 'unknown',
    );
    assert.equal(f.server.counts.token, 1);
  } finally {
    release();
    await f.close();
  }
});
test('OAuth operation bounds retain provider work until real settlement and shutdown drains it', async () => {
  const f = await fixture(),
    run = runtime(captureSettings(f.settings));
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  try {
    const pending = Array.from({ length: 32 }, () =>
      run.run({ timeoutMs: 20 }, false, async (call) => {
        await gate;
        call.check();
        return true;
      }),
    );
    const settled = Promise.allSettled(pending);
    await assert.rejects(
      run.run(undefined, false, async () => true),
      rejected('EK_BACKEND_UNAVAILABLE'),
    );
    assert.ok(
      (await settled).every(
        (result) => result.status === 'rejected' && rejected('EK_TIMEOUT')(result.reason),
      ),
    );
    await assert.rejects(
      run.run(undefined, false, async () => true),
      rejected('EK_BACKEND_UNAVAILABLE'),
    );
    let drained = false;
    const closing = run.close().then(() => {
      drained = true;
    });
    await delay(10);
    assert.equal(drained, false);
    release();
    await closing;
    await assert.rejects(
      run.run(undefined, false, async () => true),
      rejected('EK_RESOURCE_CLOSED'),
    );
  } finally {
    release();
    await run.close();
    await f.close();
  }
});
test('OAuth application shutdown retains an uncooperative secret lookup and prevents late token requests', async () => {
  const f = await fixture();
  const before = f.state.secretCalls;
  let release!: () => void;
  f.state.holdSecret = new Promise<void>((resolve) => {
    release = resolve;
  });
  const controller = new AbortController(),
    pending = f.first.oauth.clientCredentials(f.server.audience, ['orders.read'], {
      signal: controller.signal,
    });
  void pending.catch(() => undefined);
  try {
    for (let i = 0; f.state.secretCalls === before && i < 100; i++) await delay(10);
    assert.ok(f.state.secretCalls > before);
    controller.abort();
    await assert.rejects(pending);
    let stopped = false;
    const closing = f.first.app.stop().then(() => {
      stopped = true;
    });
    await delay(20);
    assert.equal(stopped, false);
    release();
    await closing;
    assert.equal(f.server.counts.token, 0);
    await assert.rejects(
      f.first.oauth.clientCredentials(f.server.audience, ['orders.read']),
      rejected('EK_RESOURCE_CLOSED'),
    );
  } finally {
    release();
    await f.close();
  }
});
test('OAuth configuration rejects insecure origins, ambiguous audience registrations and incomplete providers', async () => {
  const f = await fixture();
  try {
    for (const change of [
      { maxStateTtlMs: 0 },
      { refreshTtlMs: 0 },
      { allowInsecureLoopback: 'true' },
      { stateMacKeyRefs: f.settings.stateEncryptionKeyRefs },
      { clients: [...f.settings.clients, { ...f.settings.clients[0]!, id: 'another' }] },
      { secretProvider: {} },
      { authority: {} },
    ])
      assert.throws(() => oauthClientPlugin({ ...f.settings, ...change } as never));
    assert.equal(f.server.counts.token, 0);
  } finally {
    await f.close();
  }
});
test(
  'OAuth state is one-use across application instances and rejected issuer or redirect cannot consume it',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const start = await f.first.oauth.beginAuthorization({
          audience: f.server.audience,
          scopes: ['openid', 'orders.read'],
          returnPath: '/orders',
        }),
        callback = await f.server.authorize(start.authorizationUrl);
      await assert.rejects(
        f.second.oauth.exchangeCode({ ...callback, issuer: 'https://wrong.fixture.invalid' }),
      );
      await assert.rejects(
        f.first.oauth.exchangeCode({
          ...callback,
          redirectUri: callback.redirectUri.replace('orders', 'admin'),
        }),
      );
      const outcomes = await Promise.allSettled([
        f.first.oauth.exchangeCode(callback),
        f.second.oauth.exchangeCode(callback),
      ]);
      assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
      assert.equal(f.server.counts.token, 1);
    } finally {
      await f.close();
    }
  },
);
test(
  'OAuth verified spent refresh replay revokes the family without a second token request',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const start = await f.first.oauth.beginAuthorization({
          audience: f.server.audience,
          scopes: ['openid', 'orders.read'],
          returnPath: '/orders',
        }),
        grant = await f.first.oauth.exchangeCode(await f.server.authorize(start.authorizationUrl)),
        next = await f.second.oauth.refresh(grant.refreshRef!);
      assert.equal(f.server.counts.refresh, 1);
      await assert.rejects(f.first.oauth.refresh(grant.refreshRef!));
      await assert.rejects(f.second.oauth.refresh(next.refreshRef!));
      assert.equal(f.server.counts.refresh, 1);
    } finally {
      await f.close();
    }
  },
);
test(
  'OAuth machine grants have no cross-tenant cache and reject missing trusted runtime context',
  { timeout: 30000 },
  async () => {
    const f = await fixture();
    try {
      const a = await f.first.oauth.clientCredentials(f.server.audience, ['orders.read']);
      f.state.tenant = 'tenant-b';
      const b = await f.second.oauth.clientCredentials(f.server.audience, ['orders.read']);
      assert.notEqual(a.accessToken, b.accessToken);
      assert.equal(f.server.counts.token, 2);
      f.state.primary = false;
      await assert.rejects(f.first.oauth.clientCredentials(f.server.audience, ['orders.read']));
      assert.equal(f.server.counts.token, 2);
    } finally {
      await f.close();
    }
  },
);
