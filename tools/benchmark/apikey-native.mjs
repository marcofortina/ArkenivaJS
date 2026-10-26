// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID, randomInt } from 'node:crypto';
import { BlockList, isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';

const records = 'apikey.records.v1',
  attempts = 'apikey.attempts.v1',
  domain = 'arkenivajs.apikey.verifier.v1';
const parts = (owner) => [owner.issuer, owner.subject, owner.tenant?.tenantId ?? ''];
const binding = (owner) => JSON.stringify(parts(owner));

/** Benchmark-only positive-corpus reference: native HMAC/subnets with the same real shared providers. */
export async function directApiKeyVerifier(settings) {
  assert.equal(settings.hmac.algorithm, 'HMAC-SHA256');
  const index = async (domain, parts, options) =>
    createHash('sha256')
      .update(await settings.hmac.digest(domain, parts, settings.hmacKeyRef, options))
      .digest('hex');
  // Match the public adapter's two version-aware bootstrap reads, including its negative-lookup verifier.
  const dummy = await settings.hmac.digest(
    domain,
    ['negative', 'negative', '', randomUUID(), randomBytes(32).toString('base64url')],
    settings.hmacKeyRef,
    { timeoutMs: 5000 },
  );
  const rateOwner = await index('arkenivajs.apikey.rate-owner.v1', ['verification'], {
    timeoutMs: 5000,
  });
  return async function verify(rawKey, context) {
    const controller = new AbortController(),
      deadline = performance.now() + 5000,
      timer = setTimeout(() => controller.abort(), 5000);
    const options = () => {
      assert.ok(!controller.signal.aborted && performance.now() < deadline);
      return {
        signal: controller.signal,
        timeoutMs: Math.max(1, Math.ceil(deadline - performance.now())),
      };
    };
    try {
      const minute = Math.floor(Date.now() / 60000),
        id = 'verify-' + rateOwner + ':' + minute;
      let reserved = false;
      for (let attempt = 0; attempt < 8; attempt++) {
        const previous = await settings.store.read(attempts, id, options());
        if (previous) {
          assert.equal(previous.ownerKey, rateOwner);
          assert.equal(previous.minute, minute);
          assert.ok(Number.isSafeInteger(previous.count) && previous.count > 0);
          assert.equal(previous.kind, 'api-key-attempts-v1');
          assert.equal(previous.expiresAt, new Date((minute + 2) * 60000).toISOString());
        }
        const count = previous?.count ?? 0;
        assert.ok(count < settings.maxVerifyAttemptsPerMinute);
        const receipt = await settings.store.compareAndSet(
          attempts,
          id,
          previous?.version ?? null,
          {
            kind: 'api-key-attempts-v1',
            ownerKey: rateOwner,
            minute,
            count: count + 1,
            expiresAt: new Date((minute + 2) * 60000).toISOString(),
          },
          options(),
        );
        assert.equal(typeof receipt.committed, 'boolean');
        if (receipt.committed) {
          reserved = true;
          break;
        }
        if (attempt < 7) await delay(randomInt(1, 4), undefined, options());
      }
      assert.ok(reserved);
      const match =
          /^ak1\.([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\.([A-Za-z0-9_-]{43})$/.exec(
            rawKey,
          ),
        keyId = match?.[1] ?? '00000000-0000-4000-8000-000000000000',
        secret = match?.[2] ?? 'invalid';
      const record = await settings.store.read(records, keyId, options());
      const verified = await settings.hmac.verify(
        domain,
        record
          ? [...parts(record.subject), keyId, secret]
          : ['negative', 'negative', '', keyId, secret],
        record?.digest ?? dummy,
        settings.hmacKeyRef,
        options(),
      );
      assert.equal(verified, true);
      assert.ok(match && record);
      assert.equal(record.id, keyId);
      assert.ok(Date.parse(record.expiresAt) > Date.now());
      if (record.policy.allowedIpRanges) {
        assert.ok(context.clientIp);
        const list = new BlockList();
        for (const cidr of record.policy.allowedIpRanges) {
          const [address, bits] = cidr.split('/');
          list.addSubnet(address, Number(bits), isIP(address) === 4 ? 'ipv4' : 'ipv6');
        }
        assert.ok(list.check(context.clientIp, isIP(context.clientIp) === 4 ? 'ipv4' : 'ipv6'));
      }
      const owner = await settings.authority.require(
        'apikey.verify',
        record.subject,
        {
          ...(record.subject.tenant ? { tenant: record.subject.tenant } : {}),
          apiKeyId: keyId,
          apiKeyPolicy: record.policy,
        },
        options(),
      );
      assert.equal(binding(owner), binding(record.subject));
      assert.equal(
        await index('arkenivajs.apikey.owner.v1', parts(owner), options()),
        record.ownerKey,
      );
      const fresh = await settings.store.read(records, keyId, options());
      assert.ok(fresh);
      assert.equal(fresh.version, record.version);
      assert.equal(fresh.digest, record.digest);
      assert.ok(Date.parse(fresh.expiresAt) > Date.now());
      options();
      return { subject: owner, scopes: record.policy.scopes, keyId };
    } finally {
      clearTimeout(timer);
      controller.abort();
    }
  };
}
