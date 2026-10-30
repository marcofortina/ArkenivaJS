// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const records = 'magiclink.records.v1',
  domain = 'arkenivajs.magiclink.verifier.v1';
export function magiclinkPorts(fixture) {
  const url = new URL(fixture.endpoint);
  assert.equal(url.protocol, 'http:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && !url.username && !url.password && !url.search && !url.hash);
  assert.equal(url.pathname, '/provider');
  const exchange = async (method, args) => {
    const response = await globalThis.fetch(url, {
      method: 'POST',
      headers: { authorization: 'Bearer ' + fixture.bearer, 'content-type': 'application/json' },
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
    throw new Error('The magic-link comparison exposes only scoped reads and atomic consumption');
  };
  return {
    exchange,
    store: {
      read: (...args) => exchange('read', args.slice(0, 2)),
      atomicBatch: (mutations) => exchange('atomicBatch', [mutations]),
      ...Object.fromEntries(
        ['claimOnce', 'compareAndSet', 'listByOwner', 'bumpOwnerEpoch', 'currentOwnerEpoch'].map(
          (name) => [name, deny],
        ),
      ),
    },
    hmac: {
      algorithm: 'HMAC-SHA256',
      usage: 'test-only',
      digest: (name, parts, ref) => exchange('digest', [name, parts, ref]),
      verify: (name, parts, expected, ref) => exchange('verify', [name, parts, expected, ref]),
    },
    authority: {
      usage: 'test-only',
      require: (action, subject, context) => exchange('authorize', [action, subject, context]),
    },
  };
}

export function magiclinkSettings(fixture) {
  const ports = magiclinkPorts(fixture);
  return {
    stateStore: { store: ports.store, securityLevel: 'test-only', operationTimeoutMs: 5000 },
    hmac: ports.hmac,
    authority: ports.authority,
    signingKeyRef: fixture.keyRef,
    trustedBaseUrl: fixture.trustedBaseUrl,
    ttlMs: 300000,
    maxClaimsPerHour: 64,
  };
}

/** Positive-corpus consumption reference uses the same external HMAC, authority and SQL atomic batch. */
export function nativeMagiclink(fixture) {
  const { store, hmac, authority } = magiclinkPorts(fixture);
  return {
    async consume(token, context) {
      assert.equal(context.method, 'POST');
      const match = /^ml1\.([0-9a-f-]{36})\.([A-Za-z0-9_-]{43})$/.exec(token);
      assert.ok(match);
      const [, id, secret] = match;
      for (let attempt = 0; attempt < 8; attempt++) {
        const record = await store.read(records, id);
        assert.ok(record && record.kind === 'magic-link-v1');
        const parts = [
          record.id,
          record.owner.issuer,
          record.owner.subject,
          record.owner.tenantId,
          record.ownerKey,
          record.intent,
          record.validUntil,
          secret,
        ];
        assert.equal(await hmac.verify(domain, parts, record.digest, fixture.keyRef), true);
        assert.equal(record.intent, context.purpose);
        assert.ok(Date.now() < Date.parse(record.validUntil));
        assert.equal(record.state, 'issued');
        const subject = await authority.require(
          'magiclink.consume.' + context.purpose,
          { issuer: record.owner.issuer, subject: record.owner.subject },
          { magicLink: { issueId: id, intent: context.purpose, tenantId: record.owner.tenantId } },
        );
        assert.equal(subject.issuer, record.owner.issuer);
        assert.equal(subject.subject, record.owner.subject);
        assert.equal(subject.tenant?.tenantId ?? '', record.owner.tenantId);
        const hour = Math.floor(Date.now() / 3600000),
          quotaId = createHash('sha256')
            .update(record.ownerKey + ':' + hour)
            .digest('hex');
        const quota = await store.read('magiclink.quota.consume.v1', quotaId),
          count = quota?.count ?? 0;
        assert.ok(count < 64);
        const { version, ...nextRecord } = record;
        const result = await store.atomicBatch([
          {
            namespace: 'magiclink.quota.consume.v1',
            id: quotaId,
            ownerKey: record.ownerKey,
            expectedVersion: quota?.version ?? null,
            next: {
              kind: 'magic-link-quota-v1',
              ownerKey: record.ownerKey,
              hour,
              count: count + 1,
              expiresAt: new Date((hour + 1) * 3600000).toISOString(),
            },
          },
          {
            namespace: records,
            id,
            ownerKey: record.ownerKey,
            expectedVersion: version,
            next: { ...nextRecord, state: 'consumed' },
          },
        ]);
        if (result.committed)
          return { subject, intent: context.purpose, verifiedAt: new Date().toISOString() };
      }
      throw new Error('The native magic-link consumption retry budget was exhausted');
    },
  };
}

export async function verifyMagiclink(service, fixture) {
  const { exchange } = magiclinkPorts(fixture),
    grant = await exchange('grant', []);
  await assert.rejects(service.consume(grant.token, { method: 'GET', purpose: 'login' }));
  await assert.rejects(service.consume(grant.token, { method: 'POST', purpose: 'email-verify' }));
  const context = { method: 'POST', purpose: 'login' };
  const outcomes = await Promise.allSettled([
    service.consume(grant.token, context),
    service.consume(grant.token, context),
  ]);
  assert.equal(outcomes.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(outcomes.filter((result) => result.status === 'rejected').length, 1);
  const result = outcomes.find((result) => result.status === 'fulfilled').value;
  assert.equal(result.intent, 'login');
  assert.equal(typeof result.subject.issuer, 'string');
  assert.equal(typeof result.subject.subject, 'string');
  assert.ok(Number.isFinite(Date.parse(result.verifiedAt)));
  await assert.rejects(service.consume(grant.token, context));
  return {
    actualConsumeVerified: true,
    concurrentWinnerCount: 1,
    concurrentLoserCount: 1,
    replayRejected: true,
    getPrefetchRejected: true,
    wrongPurposeRejected: true,
  };
}
