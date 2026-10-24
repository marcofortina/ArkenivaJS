import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT, UnsecuredJWT } from 'jose';
import type { JWTPayload } from 'jose';
import { KitError, createApplication, COMPONENTS } from '@arkenivajs/core';
import type { Plugin, Logger } from '@arkenivajs/core';
import { createAuthService, securityPlugin } from '@arkenivajs/security';
import type { AuthOptions, AuthObservation } from '@arkenivajs/security';
import { createApi, apiPlugin } from '@arkenivajs/api';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
const primary = await generateKeyPair('RS256');
const rotated = await generateKeyPair('RS256');
const publicKey = {
  ...(await exportJWK(primary.publicKey)),
  kid: 'first',
  alg: 'RS256',
  use: 'sig',
};
const nextKey = { ...(await exportJWK(rotated.publicKey)), kid: 'next', alg: 'RS256', use: 'sig' };
const audience = 'api://orders-example';
async function issuer() {
  let keys = [publicKey],
    requests = 0;
  let mode: 'normal' | 'mismatch' | 'outside' | 'broken' | 'hang' | 'status' | 'discoveryJson' =
    'normal';
  const server = createServer((request, reply) => {
    if (mode === 'hang') return;
    if (mode === 'status') {
      reply.statusCode = 503;
      reply.end();
      return;
    }
    reply.setHeader('content-type', 'application/json');
    if (request.url === '/keys') {
      requests++;
      reply.end(mode === 'broken' ? '{' : JSON.stringify({ keys }));
    } else if (mode === 'discoveryJson') reply.end('{');
    else
      reply.end(
        JSON.stringify({
          issuer: mode === 'mismatch' ? 'https://untrusted.invalid' : origin,
          jwks_uri: mode === 'outside' ? 'https://outside.invalid/keys' : origin + '/keys',
        }),
      );
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const origin = `http://127.0.0.1:${address.port}`;
  return {
    origin,
    options: {
      issuer: origin,
      audience,
      environment: 'test',
      allowInsecureLoopback: true,
      jwksCooldownMs: 0,
    } satisfies AuthOptions,
    mode(value: typeof mode) {
      mode = value;
    },
    rotate() {
      keys = [nextKey];
    },
    requests: () => requests,
    async bearer(
      claims: JWTPayload = {},
      key: CryptoKey = primary.privateKey,
      kid = 'first',
      typ = 'JWT',
    ) {
      const jwt = await new SignJWT({
        tenant_id: 'tenant-A',
        scope: 'orders:read orders:write',
        ...claims,
      })
        .setProtectedHeader({ alg: 'RS256', kid, typ })
        .setSubject('example-user')
        .setIssuer(typeof claims.iss === 'string' ? claims.iss : origin)
        .setAudience(claims.aud ?? audience)
        .setExpirationTime(claims.exp ?? '5m')
        .sign(key);
      return `Bearer ${jwt}`;
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

test('EK-AUTH-001 discovery verifies signature, issuer, audience, scopes and immutable tenant provenance', async () => {
  const source = await issuer();
  const events: AuthObservation[] = [];
  const auth = await createAuthService({
    ...source.options,
    onObservation: (event) => events.push(event),
  });
  try {
    const identity = await auth.verifyBearer(await source.bearer());
    assert.equal(identity.subject, 'example-user');
    assert.deepEqual(identity.audience, [audience]);
    assert.equal(Object.isFrozen(identity.claims), true);
    auth.requireScope(identity, 'orders:read');
    assert.throws(() => auth.requireScope(identity, 'admin'), code('EK_AUTH_FORBIDDEN'));
    const tenant = auth.tenantFrom(identity);
    assert.equal(tenant.tenantId, 'tenant-A');
    assert.equal(tenant.identity, identity);
    assert.equal(tenant.source, 'oidc');
    assert.equal(auth.tenantFrom(identity), tenant);
    assert.equal(auth.isVerifiedTenant(tenant), true);
    assert.equal(auth.isVerifiedTenant({ ...tenant }), false);
    assert.equal(auth.isVerifiedTenant({ tenantId: 'tenant-B' }), false);
    assert.equal(auth.isVerifiedTenant(null), false);
    assert.throws(
      () => auth.requireScope({ ...identity }, 'orders:read'),
      code('EK_AUTH_FORBIDDEN'),
    );
    assert.throws(() => auth.tenantFrom({ ...identity }), code('EK_TENANT_UNVERIFIED'));
    assert.ok(!JSON.stringify(events).includes('tenant-A'));
    assert.deepEqual(auth.stats(), { verified: 1, rejected: 0, observerFailures: 0 });
    await auth.close();
    await auth.close();
    assert.equal(auth.isVerifiedTenant(tenant), false);
    await assert.rejects(auth.verifyBearer(await source.bearer()), code('EK_RESOURCE_CLOSED'));
    assert.throws(() => auth.tenantFrom(identity), code('EK_RESOURCE_CLOSED'));
    assert.throws(() => auth.requireScope(identity, 'orders:read'), code('EK_RESOURCE_CLOSED'));
  } finally {
    await auth.close();
    await source.close();
  }
});

test('EK-AUTH-001 token confusion and malformed assertions never create a verified identity', async () => {
  const source = await issuer();
  const auth = await createAuthService(source.options);
  try {
    for (const value of [undefined, ''])
      await assert.rejects(auth.verifyBearer(value), code('EK_AUTH_REQUIRED'));
    for (const value of [
      'Basic fake',
      'Bearer fake',
      'Bearer ' + 'x'.repeat(16384),
      'Bearer a.b.c',
      ' Bearer a.b.c',
      'Bearer ' + new UnsecuredJWT({ sub: 'forged' }).encode(),
      await source.bearer({ iss: 'https://wrong.invalid' }),
      await source.bearer({ aud: 'api://other' }),
      await source.bearer({ exp: Math.floor(Date.now() / 1000) - 100 }),
      await source.bearer({ nbf: Math.floor(Date.now() / 1000) + 100 }),
      await source.bearer({}, rotated.privateKey),
      await source.bearer({}, primary.privateKey, 'first', 'id+jwt'),
      await source.bearer({ scope: ['orders:read'] }),
      await source.bearer({ scope: 'read\nwrite' }),
      await source.bearer({ scope: 'x'.repeat(4097) }),
    ])
      await assert.rejects(auth.verifyBearer(value), code('EK_AUTH_INVALID'));
    const bad = await new SignJWT({ sub: 'user', iss: source.origin, aud: audience })
      .setProtectedHeader({ alg: 'RS256', kid: 'first', typ: 'JWT' })
      .sign(primary.privateKey);
    await assert.rejects(auth.verifyBearer('Bearer ' + bad), code('EK_AUTH_INVALID'));
    assert.equal(auth.stats().verified, 0);
  } finally {
    await auth.close();
    await source.close();
  }
});

test('EK-AUTH-002 missing, ambiguous, hostile and unauthorized claims reject despite valid signatures', async () => {
  const source = await issuer();
  const auth = await createAuthService({
    ...source.options,
    authorizeTenant: (_identity, tenant) => tenant !== 'denied',
  });
  try {
    for (const claim of [
      null,
      undefined,
      [],
      ['tenant-A', 'tenant-B'],
      '',
      'bad tenant',
      '../other',
      'a\nb',
      'x'.repeat(129),
      'denied',
    ]) {
      const identity = await auth.verifyBearer(await source.bearer({ tenant_id: claim }));
      assert.throws(() => auth.tenantFrom(identity), code('EK_TENANT_UNVERIFIED'));
    }
    const custom = await createAuthService({
      ...source.options,
      tenantClaim: 'organization',
      authorizeTenant() {
        throw new Error('fake-policy-secret');
      },
    });
    try {
      const identity = await custom.verifyBearer(await source.bearer({ organization: 'tenant-A' }));
      assert.throws(() => custom.tenantFrom(identity), code('EK_TENANT_UNVERIFIED'));
    } finally {
      await custom.close();
    }
    const scoped = await auth.verifyBearer(
      await source.bearer({ scope: undefined, scp: 'orders:read' }),
    );
    auth.requireScope(scoped, 'orders:read');
    const empty = await auth.verifyBearer(await source.bearer({ scope: undefined }));
    assert.deepEqual(empty.scopes, []);
  } finally {
    await auth.close();
    await source.close();
  }
});

test('EK-AUTH-001 rotating JWKS refreshes for an unknown key and shared concurrent requests remain isolated', async () => {
  const source = await issuer();
  const auth = await createAuthService(source.options);
  try {
    await auth.verifyBearer(await source.bearer());
    source.rotate();
    const token = await source.bearer({}, rotated.privateKey, 'next');
    const identities = await Promise.all(
      Array.from({ length: 12 }, () => auth.verifyBearer(token)),
    );
    assert.equal(source.requests(), 2);
    assert.ok(identities.every((identity) => auth.tenantFrom(identity).tenantId === 'tenant-A'));
    await assert.rejects(auth.verifyBearer(await source.bearer()), code('EK_AUTH_INVALID'));
  } finally {
    await auth.close();
    await source.close();
  }
});

test('EK-AUTH-001 discovery, malformed JWKS, transport cancellation and deadline failures are bounded', async () => {
  const source = await issuer();
  try {
    for (const mode of ['mismatch', 'outside', 'status', 'discoveryJson'] as const) {
      source.mode(mode);
      await assert.rejects(createAuthService(source.options), code('EK_CONFIG_INVALID'));
    }
    source.mode('broken');
    const auth = await createAuthService(source.options);
    try {
      await assert.rejects(auth.verifyBearer(await source.bearer()), code('EK_AUTH_INVALID'));
    } finally {
      await auth.close();
    }
    source.mode('hang');
    await assert.rejects(createAuthService(source.options, { timeoutMs: 20 }), code('EK_TIMEOUT'));
    await assert.rejects(
      createAuthService(source.options, { signal: AbortSignal.abort() }),
      code('EK_ABORTED'),
    );
    const hanging = await createAuthService({
      ...source.options,
      jwksUrl: source.origin + '/keys',
    });
    try {
      await assert.rejects(
        hanging.verifyBearer(await source.bearer(), { timeoutMs: 20 }),
        code('EK_TIMEOUT'),
      );
      await assert.rejects(
        hanging.verifyBearer(await source.bearer(), { signal: AbortSignal.abort() }),
        code('EK_ABORTED'),
      );
      await hanging.close();
    } finally {
      await hanging.close();
    }
  } finally {
    await source.close();
  }
});

test('EK-AUTH-001 invalid policies fail before I/O and observer failures cannot change authentication', async () => {
  const source = await issuer();
  try {
    for (const policy of [
      { algorithms: ['none'] },
      { algorithms: 'RS256' },
      { allowedJwksOrigins: 3 },
      { issuer: 3 },
      { jwksUrl: 3 },
      { algorithms: ['HS256'] },
      { algorithms: [] },
      { algorithms: ['RS256', 'RS256'] },
      { audience: '' },
      { tenantClaim: '__proto__' },
      { issuer: 'https://user:fake@issuer.invalid' },
      { issuer: 'http://example.invalid' },
      { issuer: 'https://issuer.invalid/#bad' },
      { issuer: 'bad' },
      { clockToleranceSeconds: 61 },
      { clockToleranceSeconds: NaN },
      { jwksCooldownMs: -1 },
      { jwksCacheMaxAgeMs: 0 },
      { tokenType: 'id+jwt' },
      { environment: 'prod' },
      { allowInsecureLoopback: 'yes' },
      { authorizeTenant: 1 },
      { onObservation: 1 },
      { environment: 'production' },
      { allowedJwksOrigins: ['https://keys.invalid/path'] },
    ])
      await assert.rejects(
        createAuthService({ ...source.options, ...policy } as AuthOptions),
        code('EK_CONFIG_INVALID'),
      );
    const auth = await createAuthService({
      ...source.options,
      tokenType: 'at+jwt',
      onObservation() {
        throw new Error('fake-observer');
      },
    });
    try {
      const identity = await auth.verifyBearer(
        await source.bearer({}, primary.privateKey, 'first', 'at+jwt'),
      );
      assert.equal(auth.tenantFrom(identity).tenantId, 'tenant-A');
      assert.equal(auth.stats().observerFailures, 1);
    } finally {
      await auth.close();
    }
  } finally {
    await source.close();
  }
});

test('EK-AUTH-002 protected REST ignores forged headers and applies tenant predicates before data access', async () => {
  const source = await issuer();
  const auth = await createAuthService(source.options);
  const api = createApi({
    service: { name: 'tenant-test', version: '1.0.0', environment: 'test' },
    port: 0,
    auth,
  });
  const rows = [
    { id: 'a', tenant: 'tenant-A' },
    { id: 'b', tenant: 'tenant-B' },
  ];
  api.get<{ id: string }, Record<string, never>, never, { id: string }>('/records/:id', {
    schema: {
      response: {
        type: 'object',
        properties: { id: { type: 'string' } },
        required: ['id'],
        additionalProperties: false,
      },
    },
    auth: { required: true, scopes: ['orders:read'] },
    handler(context) {
      const row = rows.find(
        (row) => row.id === context.params.id && row.tenant === context.auth!.tenantId,
      );
      if (!row)
        throw new KitError({ code: 'EK_HTTP_NOT_FOUND', message: 'Tenant record not found' });
      return { id: row.id };
    },
  });
  try {
    await api.start();
    const bearer = await source.bearer();
    const headers = {
      authorization: bearer,
      'x-tenant-id': 'tenant-B',
      baggage: 'tenant_id=tenant-B',
    };
    const allowed = await fetch(api.address() + '/records/a', { headers });
    assert.equal(allowed.status, 200);
    assert.deepEqual(await allowed.json(), { id: 'a' });
    const denied = await fetch(api.address() + '/records/b', { headers });
    assert.equal(denied.status, 404);
    assert.ok(!JSON.stringify(await denied.json()).includes('tenant-B'));
    assert.equal(
      (await fetch(api.address() + '/records/b', { headers: { 'x-tenant-id': 'tenant-B' } }))
        .status,
      401,
    );
  } finally {
    await api.close();
    await auth.close();
    await source.close();
  }
});

const quiet = (): Logger => {
  const log = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    setLevel() {},
    flush: async () => {},
    child: () => log,
  };
  return log;
};
const logging: Plugin = {
  id: 'logging',
  version: '1.0.0',
  capabilities: new Set(['logger']),
  init(ctx) {
    ctx.provide(COMPONENTS.logger, quiet());
  },
  close() {},
};

test('EK-AUTH-001 application verifiers are independent when a plugin factory is reused', async () => {
  const source = await issuer();
  const plugin = securityPlugin({ allowInsecureLoopback: true, jwksCooldownMs: 0 });
  const first = await createApplication({
    service: { name: 'auth-a', version: '1.0.0', environment: 'test' },
    security: { issuer: source.origin, audience },
    plugins: [logging, plugin],
  });
  const second = await createApplication({
    service: { name: 'auth-b', version: '1.0.0', environment: 'test' },
    security: { issuer: source.origin, audience },
    plugins: [logging, plugin],
  });
  try {
    await first.start();
    await second.start();
    const identity = await first.auth!.verifyBearer(await source.bearer());
    assert.throws(() => second.auth!.tenantFrom(identity), code('EK_TENANT_UNVERIFIED'));
    await first.stop();
    await second.auth!.verifyBearer(await source.bearer());
  } finally {
    await first.stop();
    await second.stop();
    await source.close();
  }
  const missing = await createApplication({
    service: { name: 'auth-missing', version: '1.0.0', environment: 'test' },
    plugins: [logging, plugin],
  });
  await assert.rejects(missing.start(), code('EK_PLUGIN_FAILED'));
  await missing.stop();
});

test('EK-AUTH-001 asymmetric allowlists reject real HMAC assertions and malformed subjects', async () => {
  const source = await issuer();
  const auth = await createAuthService(source.options);
  try {
    const signed = async (alg: string, key: CryptoKey | Uint8Array, claims: JWTPayload) =>
      'Bearer ' +
      (await new SignJWT({
        iss: source.origin,
        aud: audience,
        exp: Math.floor(Date.now() / 1000) + 120,
        ...claims,
      })
        .setProtectedHeader({ alg, kid: 'first', typ: 'JWT' })
        .sign(key));
    await assert.rejects(
      auth.verifyBearer(await signed('HS256', new Uint8Array(32).fill(17), { sub: 'user' })),
      code('EK_AUTH_INVALID'),
    );
    for (const sub of ['', 'bad subject', 'x'.repeat(513)])
      await assert.rejects(
        auth.verifyBearer(await signed('RS256', primary.privateKey, { sub })),
        code('EK_AUTH_INVALID'),
      );
    const identity = await auth.verifyBearer(
      await source.bearer({
        aud: [audience, 'api://additional'],
        nbf: Math.floor(Date.now() / 1000) - 10,
      }),
    );
    assert.deepEqual(identity.audience, [audience, 'api://additional']);
  } finally {
    await auth.close();
    await source.close();
  }
});

test('EK-AUTH-002 retained contexts lose provenance when their signed authorization expires', async () => {
  const source = await issuer();
  const auth = await createAuthService({ ...source.options, clockToleranceSeconds: 0 });
  try {
    const exp = Math.floor(Date.now() / 1000) + 2;
    const identity = await auth.verifyBearer(await source.bearer({ exp }));
    const tenant = auth.tenantFrom(identity);
    assert.equal(auth.isVerifiedTenant(tenant), true);
    await new Promise((resolve) => setTimeout(resolve, Math.max(0, exp * 1000 - Date.now() + 20)));
    assert.equal(auth.isVerifiedTenant(tenant), false);
    assert.throws(() => auth.tenantFrom(identity), code('EK_TENANT_UNVERIFIED'));
    assert.throws(() => auth.requireScope(identity, 'orders:read'), code('EK_AUTH_FORBIDDEN'));
  } finally {
    await auth.close();
    await source.close();
  }
});

test('EK-AUTH-001 default production policy and explicitly authorized key origins remain resource-free until verification', async () => {
  const auth = await createAuthService({
    issuer: 'https://issuer.example.invalid',
    audience,
    jwksUrl: 'https://keys.example.invalid/keys',
    allowedJwksOrigins: ['https://keys.example.invalid'],
  });
  try {
    assert.throws(() => auth.tenantFrom(null as never), code('EK_TENANT_UNVERIFIED'));
    assert.throws(() => auth.requireScope(null as never, ''), code('EK_AUTH_FORBIDDEN'));
    await assert.rejects(auth.verifyBearer(undefined), code('EK_AUTH_REQUIRED'));
  } finally {
    await auth.close();
  }
  await assert.rejects(
    createAuthService({
      issuer: 'https://issuer.example.invalid',
      audience,
      jwksUrl: 'https://keys.example.invalid/keys',
    }),
    code('EK_CONFIG_INVALID'),
  );
});

test('EK-AUTH-001 plugin setup failures close the verifier and observations remain metadata-only', async () => {
  const source = await issuer();
  const events: unknown[] = [];
  const plugin = securityPlugin({
    allowInsecureLoopback: true,
    onObservation(event) {
      events.push(event);
    },
  });
  const options = {
    service: { name: 'auth-hook', version: '1.0.0', environment: 'test' as const },
    security: { issuer: source.origin, audience },
    plugins: [],
  };
  let auth: import('@arkenivajs/security').ManagedAuthService | undefined;
  try {
    const context = {
      logger: quiet(),
      options,
      provide<T>(_key: symbol, value: T) {
        auth = value as typeof auth;
        throw new Error('fake-registration-failure');
      },
      require<T>(): T {
        return new AbortController().signal as T;
      },
    };
    await assert.rejects(Promise.resolve(plugin.init(context)), /fake-registration-failure/);
    assert.ok(auth);
    await assert.rejects(auth.verifyBearer(await source.bearer()), code('EK_RESOURCE_CLOSED'));
    const app = await createApplication({ ...options, plugins: [logging, plugin] });
    try {
      await app.start();
      await app.auth!.verifyBearer(await source.bearer());
      assert.deepEqual(events, [{ outcome: 'verified' }]);
    } finally {
      await app.stop();
    }
  } finally {
    await source.close();
  }
});

test('MFA-AUTH-001 only explicit issuer mapping and current freshness grant assurance to provider-owned identities', async () => {
  const source = await issuer();
  let evaluations = 0;
  let now = Math.floor(Date.now() / 1000);
  const auth = await createAuthService({
    ...source.options,
    assuranceResolver(identity) {
      evaluations++;
      assert.equal(identity.issuer, source.origin);
      assert.ok(Object.isFrozen(identity));
      const { acr, amr, auth_time: authenticatedAt } = identity.claims;
      if (
        typeof authenticatedAt !== 'number' ||
        now - authenticatedAt > 60 ||
        authenticatedAt > now
      )
        return 'single-factor';
      if (acr === 'urn:example:webauthn' && Array.isArray(amr) && amr.includes('fido2'))
        return 'phishing-resistant';
      if (acr === 'urn:example:mfa' && Array.isArray(amr) && amr.includes('otp')) return 'mfa';
      return 'single-factor';
    },
  });
  const foreign = await createAuthService({
    ...source.options,
    assuranceResolver: () => 'phishing-resistant',
  });
  try {
    assert.equal(auth.hasAssurancePolicy(), true);
    await assert.rejects(
      auth.verifyBearer(await source.bearer({ aud: 'wrong-audience' })),
      code('EK_AUTH_INVALID'),
    );
    assert.equal(evaluations, 0);
    const single = await auth.verifyBearer(
      await source.bearer({ mfa: true, amr: ['mfa'], auth_time: now }),
    );
    assert.equal(single.assurance, 'single-factor');
    auth.requireAssurance(single, 'single-factor');
    assert.throws(() => auth.requireAssurance(single, 'mfa'), code('EK_MFA_ASSURANCE_REQUIRED'));
    const mfa = await auth.verifyBearer(
      await source.bearer({ acr: 'urn:example:mfa', amr: ['otp'], auth_time: now }),
    );
    assert.equal(mfa.assurance, 'mfa');
    auth.requireAssurance(mfa, 'mfa');
    assert.throws(
      () => auth.requireAssurance(mfa, 'phishing-resistant'),
      code('EK_MFA_ASSURANCE_REQUIRED'),
    );
    const high = await auth.verifyBearer(
      await source.bearer({ acr: 'urn:example:webauthn', amr: ['fido2'], auth_time: now }),
    );
    auth.requireAssurance(high, 'phishing-resistant');
    const stale = await auth.verifyBearer(
      await source.bearer({ acr: 'urn:example:webauthn', amr: ['fido2'], auth_time: now - 61 }),
    );
    assert.equal(stale.assurance, 'single-factor');
    const other = await foreign.verifyBearer(await source.bearer());
    const prior = evaluations;
    for (const forged of [null, { ...high }, { ...single, assurance: 'phishing-resistant' }, other])
      assert.throws(
        () => auth.requireAssurance(forged as never, 'mfa'),
        code('EK_MFA_ASSURANCE_REQUIRED'),
      );
    assert.equal(evaluations, prior);
    assert.throws(() => auth.requireAssurance(high, 'invalid' as never), code('EK_MFA_POLICY'));
    now += 61;
    assert.throws(() => auth.requireAssurance(high, 'mfa'), code('EK_MFA_ASSURANCE_REQUIRED'));
    await auth.close();
    assert.equal(auth.hasAssurancePolicy(), false);
    assert.throws(() => auth.requireAssurance(high, 'mfa'), code('EK_RESOURCE_CLOSED'));
  } finally {
    await auth.close();
    await foreign.close();
    await source.close();
  }
});

test('MFA-AUTH-001 missing, invalid and failing assurance resolvers cannot fabricate elevated proof', async () => {
  const source = await issuer();
  const absent = await createAuthService(source.options);
  try {
    const identity = await absent.verifyBearer(
      await source.bearer({ assurance: 'mfa', mfa: true }),
    );
    assert.equal(identity.assurance, undefined);
    assert.equal(absent.hasAssurancePolicy(), false);
    assert.throws(
      () => absent.requireAssurance(identity, 'mfa'),
      code('EK_MFA_ASSURANCE_REQUIRED'),
    );
    await assert.rejects(
      createAuthService({ ...source.options, assuranceResolver: 'mfa' as never }),
      code('EK_MFA_POLICY'),
    );
    for (const resolve of [
      () => 'unknown',
      () => {
        throw new Error('fake-policy-secret');
      },
      async () => {
        throw new Error('fake-async-secret');
      },
    ]) {
      const auth = await createAuthService({
        ...source.options,
        assuranceResolver: resolve as never,
      });
      try {
        await assert.rejects(auth.verifyBearer(await source.bearer()), (error) => {
          assert.ok(code('EK_MFA_POLICY')(error));
          assert.ok(!JSON.stringify(error).includes('fake-'));
          return true;
        });
        assert.equal(auth.stats().verified, 0);
      } finally {
        await auth.close();
      }
    }
  } finally {
    await absent.close();
    await source.close();
  }
});

test('MFA-AUTH-001 REST rejects insufficient assurance before tenant resolution, middleware and handler execution', async () => {
  const source = await issuer();
  const auth = await createAuthService({
    ...source.options,
    assuranceResolver: (identity) =>
      identity.claims.acr === 'urn:example:trusted-mfa' ? 'mfa' : 'single-factor',
  });
  const api = createApi({
    service: { name: 'assurance-rest', version: '1.0.0', environment: 'test' },
    port: 0,
    auth,
  });
  let calls = 0;
  api.registerMiddleware('postAuthentication', async (_ctx, next) => {
    calls++;
    await next();
  });
  api.get('/sensitive', {
    schema: {
      response: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'] },
    },
    auth: { required: true, scopes: ['orders:read'], assurance: 'mfa' },
    handler: () => {
      calls++;
      return { value: 'ok' };
    },
  });
  try {
    await api.start();
    assert.equal((await api.native().inject('/sensitive')).statusCode, 401);
    const denied = await api.native().inject({
      url: '/sensitive',
      headers: {
        authorization: await source.bearer({ mfa: true, tenant_id: null }),
        'x-mfa': 'true',
        baggage: 'assurance=mfa',
      },
    });
    assert.equal(denied.statusCode, 403);
    assert.equal(denied.json().error.code, 'EK_MFA_ASSURANCE_REQUIRED');
    assert.equal(calls, 0);
    const accepted = await api.native().inject({
      url: '/sensitive',
      headers: { authorization: await source.bearer({ acr: 'urn:example:trusted-mfa' }) },
    });
    assert.equal(accepted.statusCode, 200);
    assert.equal(calls, 2);
    assert.ok(JSON.stringify(api.openApiDocument()).includes('x-arkenivajs-assurance'));
  } finally {
    await api.close();
    await auth.close();
    await source.close();
  }
});

test('MFA-AUTH-001 application startup retains the policy failure code and rolls back before listener binding', async () => {
  const source = await issuer();
  const app = await createApplication({
    service: { name: 'assurance-application', version: '1.0.0', environment: 'test' },
    security: { issuer: source.origin, audience },
    plugins: [
      logging,
      securityPlugin({ allowInsecureLoopback: true, jwksCooldownMs: 0 }),
      apiPlugin({ dependencies: ['security'] }),
    ],
  });
  app.api!.get('/sensitive', {
    schema: { response: { type: 'object' } },
    auth: { required: true, assurance: 'mfa' },
    handler: () => {
      throw new Error('Assurance-protected handler must remain unreachable');
    },
  });
  try {
    await assert.rejects(app.start(), code('EK_MFA_POLICY'));
    assert.equal(app.state, 'CLOSED');
  } finally {
    await app.stop();
    await source.close();
  }
});
