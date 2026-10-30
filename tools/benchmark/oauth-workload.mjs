// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as native from 'openid-client';

export function oauthPorts(fixture) {
  const endpoint = new URL(fixture.endpoint),
    issuer = new URL(fixture.issuer);
  assert.equal(endpoint.protocol, 'http:');
  assert.equal(endpoint.hostname, '127.0.0.1');
  assert.equal(endpoint.pathname, '/provider');
  assert.equal(endpoint.origin + endpoint.pathname, fixture.endpoint);
  assert.ok(endpoint.port);
  assert.equal(issuer.protocol, 'https:');
  assert.equal(issuer.hostname, '127.0.0.1');
  assert.equal(issuer.origin, fixture.issuer);
  assert.ok(issuer.port);
  const exchange = async (method, args) => {
    const response = await globalThis.fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-owned-provider': fixture.bearer },
      body: JSON.stringify({ method, args }),
      signal: AbortSignal.timeout(5000),
      redirect: 'error',
    });
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.ok(Buffer.byteLength(body) <= 16384);
    return JSON.parse(body).result;
  };
  const deny = async () => {
    throw new Error('The machine grant comparison exposes only durable budget operations');
  };
  return {
    authority: {
      usage: 'test-only',
      require: (action, _hint, context) => exchange('authorize', [action, context]),
    },
    secretProvider: {
      usage: 'test-only',
      async get(reference) {
        const value = await exchange('secret', [reference]);
        return { bytes: Buffer.from(value.encoded, 'base64url'), keyVersion: value.version };
      },
    },
    store: {
      securityLevel: 'test-only',
      read: (namespace, id) => exchange('read', [namespace, id]),
      compareAndSet: (namespace, id, expected, next) =>
        exchange('compareAndSet', [namespace, id, expected, next]),
      ...Object.fromEntries(
        ['claimOnce', 'atomicBatch', 'listByOwner', 'bumpOwnerEpoch', 'currentOwnerEpoch'].map(
          (name) => [name, deny],
        ),
      ),
    },
  };
}

export function oauthSettings(fixture, ports = oauthPorts(fixture)) {
  return {
    clients: [
      {
        id: 'owned',
        issuer: fixture.issuer,
        clientId: fixture.clientId,
        clientSecretRef: 'client',
        redirectUri: fixture.redirectUri,
        allowedAudiences: [fixture.audience],
        allowedScopes: ['orders.read'],
      },
    ],
    secretProvider: ports.secretProvider,
    authority: ports.authority,
    stateStore: { store: ports.store, securityLevel: 'test-only', operationTimeoutMs: 10000 },
    maxStateTtlMs: 300000,
    stateEncryptionKeyRefs: ['enc'],
    stateMacKeyRefs: ['mac'],
    allowInsecureLoopback: true,
  };
}

async function reserve(store) {
  const minute = Math.floor(Date.now() / 60000),
    key = 'grant:' + minute;
  const ownerKey = createHash('sha256')
    .update('arkenivajs.oauth.technical-budget.v1')
    .digest('hex');
  for (let attempt = 0; attempt < 8; attempt++) {
    const previous = await store.read('oauth.budgets.v1', key);
    const count = previous?.count ?? 0;
    assert.ok(Number.isSafeInteger(count) && count >= 0 && count < 1000);
    const receipt = await store.compareAndSet('oauth.budgets.v1', key, previous?.version ?? null, {
      kind: 'oauth-budget-v1',
      ownerKey,
      minute,
      count: count + 1,
      expiresAt: new Date((minute + 2) * 60000).toISOString(),
    });
    if (receipt.committed) return;
  }
  throw new Error('The owned native OAuth budget could not be reserved');
}

/** Native SDK discovery and authenticated grants retain the same actual SQL technical budget. */
export async function nativeOAuth(fixture) {
  const ports = oauthPorts(fixture),
    secret = await ports.secretProvider.get('client');
  let authentication;
  try {
    authentication = native.ClientSecretBasic(secret.bytes.toString('utf8'));
  } finally {
    secret.bytes.fill(0);
  }
  const config = await native.discovery(
    new URL(fixture.issuer),
    fixture.clientId,
    undefined,
    authentication,
  );
  config.timeout = 5;
  return {
    async clientCredentials(audience, scopes) {
      assert.equal(audience, fixture.audience);
      assert.deepEqual(scopes, ['orders.read']);
      await reserve(ports.store);
      await ports.authority.require('oauth.client_credentials', undefined, {
        oauth: { clientId: 'owned', audience, scopes },
      });
      const result = await native.clientCredentialsGrant(config, {
        resource: audience,
        scope: scopes.join(' '),
      });
      assert.equal(result.token_type.toLowerCase(), 'bearer');
      assert.ok(Number.isSafeInteger(result.expires_in) && result.expires_in > 0);
      return {
        accessToken: result.access_token,
        tokenType: 'Bearer',
        expiresAt: new Date(Date.now() + result.expires_in * 1000).toISOString(),
        scopes: result.scope.split(' '),
        audience,
      };
    },
  };
}

export async function verifyOAuth(service, fixture) {
  const tokens = new Set();
  for (let index = 0; index < 2; index++) {
    const started = Date.now(),
      grant = await service.clientCredentials(fixture.audience, ['orders.read']);
    assert.equal(grant.tokenType, 'Bearer');
    assert.match(grant.accessToken, /^access\.[A-Za-z0-9_-]+$/);
    assert.equal(grant.audience, fixture.audience);
    assert.deepEqual([...grant.scopes], ['orders.read']);
    assert.equal(grant.refreshRef, undefined);
    assert.ok(
      Date.parse(grant.expiresAt) >= started + 299000 &&
        Date.parse(grant.expiresAt) <= Date.now() + 301000,
    );
    tokens.add(grant.accessToken);
  }
  assert.equal(tokens.size, 2);
  await assert.rejects(service.clientCredentials(fixture.audience, ['unapproved.scope']));
  return {
    authenticatedMachineGrants: 2,
    distinctTokens: true,
    finiteExpiryVerified: true,
    approvedScopeOnly: true,
    refreshReferenceAbsent: true,
  };
}
