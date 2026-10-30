// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { magicLinkFixture } from '../../examples/postgres/dist-test/integration/magiclink-fixture.js';

/** The parent retains signed authentication, external HMAC keys and actual transactional PostgreSQL state. */
export async function startMagiclinkFixture(sampleIssues = false) {
  assert.equal(typeof sampleIssues, 'boolean');
  assert.equal(process.env.ARKENIVA_POSTGRES_DISPOSABLE, '1');
  const backend = await magicLinkFixture(64, 300000);
  const bearer = randomBytes(32).toString('base64url'),
    tasks = new Set(),
    grants = [],
    sampled = [],
    sampleOwners = [],
    sampleVerifications = new Map(),
    sampleAuthorizations = new Map(),
    sampleCounts = [0, 0, 0, 0],
    grantSessions = new Map();
  const privacyValues = [bearer, '127.0.0.1'],
    faults = { store: false, hmac: false, authority: false };
  const state = {
    handedOut: 0,
    committedBatches: 0,
    authorizationCalls: 0,
    sampleIssueRequests: 0,
  };
  let bridge, session;
  const close = async () => {
    try {
      if (bridge?.listening) {
        bridge.closeAllConnections();
        await new Promise((done) => bridge.close(done));
      }
      await Promise.allSettled([...tasks]);
    } finally {
      await backend.close();
    }
  };
  const remember = (value) => {
    if (typeof value === 'string' && value.length > 0 && !privacyValues.includes(value))
      privacyValues.push(value);
  };
  try {
    session = await backend.session();
    for (const value of [
      session.subject.issuer,
      session.subject.subject,
      session.subject.tenant.tenantId,
    ])
      remember(value);
    for (let index = 0; index < 4; index++) {
      const issued = await session.run(() => backend.first.magic.issue(session.subject, 'login'));
      grants.push({ token: issued.value, issueId: issued.issueId });
      grantSessions.set(issued.issueId, session);
      for (const value of [
        issued.value,
        issued.issueId,
        issued.value.split('.')[2],
        issued.redemptionUrl,
      ])
        remember(value);
      const record = await backend.base.backend.store.read('magiclink.records.v1', issued.issueId);
      remember(record.digest);
      remember(record.ownerKey);
    }
    if (sampleIssues)
      for (let index = 0; index < 8; index++) {
        const owner = await backend.session({
          sub: 'magiclink-sample-' + randomBytes(12).toString('hex'),
          sid: 'magiclink-session-' + randomBytes(12).toString('hex'),
        });
        sampleOwners.push(owner);
        for (const value of [
          owner.subject.issuer,
          owner.subject.subject,
          owner.subject.tenant.tenantId,
        ])
          remember(value);
      }
    bridge = createServer((request, response) => {
      if (tasks.size >= 8) {
        response.writeHead(503, { connection: 'close' }).end();
        return;
      }
      const task = (async () => {
        assert.equal(request.method, 'POST');
        assert.equal(request.url, '/provider');
        const supplied = Buffer.from(request.headers.authorization ?? ''),
          expected = Buffer.from('Bearer ' + bearer);
        assert.equal(supplied.length, expected.length);
        assert.ok(timingSafeEqual(supplied, expected));
        const chunks = [];
        let bytes = 0;
        for await (const chunk of request) {
          bytes += chunk.length;
          assert.ok(bytes <= 32768);
          chunks.push(chunk);
        }
        const { method, args } = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        assert.ok(Array.isArray(args));
        let result;
        if (method === 'grant') {
          assert.equal(args.length, 0);
          assert.ok(state.handedOut < grants.length);
          result = grants[state.handedOut++];
        } else if (method === 'sampleIssue') {
          assert.equal(sampleIssues, true);
          assert.equal(args.length, 1);
          const profile = grants.findIndex((grant) => grant.issueId === args[0]);
          assert.ok(profile >= 0 && profile < state.handedOut);
          assert.ok(sampleCounts[profile] < 120 && sampled.length < 480);
          const owner = sampleOwners[profile * 2 + (sampleCounts[profile] % 2)];
          const issued = await owner.run(() => backend.first.magic.issue(owner.subject, 'login'));
          const record = await backend.base.backend.store.read(
            'magiclink.records.v1',
            issued.issueId,
          );
          assert.equal(record.state, 'issued');
          assert.equal(
            sampled.some((grant) => grant.issueId === issued.issueId),
            false,
          );
          const grant = { token: issued.value, issueId: issued.issueId };
          sampled.push(grant);
          sampleVerifications.set(issued.issueId, 0);
          sampleAuthorizations.set(issued.issueId, 0);
          grantSessions.set(issued.issueId, owner);
          sampleCounts[profile]++;
          state.sampleIssueRequests++;
          for (const value of [
            issued.value,
            issued.issueId,
            issued.value.split('.')[2],
            issued.redemptionUrl,
            record.digest,
            record.ownerKey,
          ])
            remember(value);
          result = {
            ...grant,
            subject: {
              issuer: owner.subject.issuer,
              subject: owner.subject.subject,
              tenantId: owner.subject.tenant.tenantId,
            },
          };
        } else if (method === 'authorize') {
          assert.equal(faults.authority, false);
          assert.equal(args[0], 'magiclink.consume.login');
          assert.equal(args[2].magicLink.intent, 'login');
          const owner = grantSessions.get(args[2].magicLink.issueId);
          assert.ok(owner);
          assert.equal(args[1].issuer, owner.subject.issuer);
          assert.equal(args[1].subject, owner.subject.subject);
          state.authorizationCalls++;
          if (sampleAuthorizations.has(args[2].magicLink.issueId))
            sampleAuthorizations.set(
              args[2].magicLink.issueId,
              sampleAuthorizations.get(args[2].magicLink.issueId) + 1,
            );
          result = await owner.run(() => backend.settings.authority.require(...args));
        } else if (method === 'digest' || method === 'verify') {
          assert.equal(faults.hmac, false);
          assert.equal(args[0], 'arkenivajs.magiclink.verifier.v1');
          assert.ok(Array.isArray(args[1]) && args[1].length <= 10);
          for (const part of args[1]) {
            assert.equal(typeof part, 'string');
            assert.ok(part.length <= 2048);
            if (part.length >= 32) remember(part);
          }
          assert.equal(args[method === 'digest' ? 2 : 3], backend.settings.signingKeyRef);
          if (method === 'verify') remember(args[2]);
          if (method === 'verify' && sampleVerifications.has(args[1][0]))
            sampleVerifications.set(args[1][0], sampleVerifications.get(args[1][0]) + 1);
          result = await backend.settings.hmac[method](...args);
          if (method === 'digest') remember(result);
        } else {
          assert.equal(faults.store, false);
          if (method === 'read') {
            assert.ok(['magiclink.records.v1', 'magiclink.quota.consume.v1'].includes(args[0]));
            assert.equal(args.length, 2);
            assert.equal(typeof args[1], 'string');
            assert.ok(args[1].length <= 64);
            result = await backend.base.backend.store.read(...args);
          } else {
            assert.equal(method, 'atomicBatch');
            assert.equal(args.length, 1);
            assert.equal(args[0].length, 2);
            assert.equal(args[0][0].namespace, 'magiclink.quota.consume.v1');
            assert.equal(args[0][1].namespace, 'magiclink.records.v1');
            assert.ok(grantSessions.has(args[0][1].id));
            assert.equal(args[0][1].next.state, 'consumed');
            result = await backend.base.backend.store.atomicBatch(args[0]);
            if (result.committed) state.committedBatches++;
          }
        }
        response
          .writeHead(200, { 'content-type': 'application/json' })
          .end(JSON.stringify({ result }));
      })()
        .catch(() => response.writeHead(400).end())
        .finally(() => tasks.delete(task));
      tasks.add(task);
    });
    await new Promise((done, reject) => {
      bridge.once('error', reject);
      bridge.listen(0, '127.0.0.1', done);
    });
    const fixture = {
      endpoint: 'http://127.0.0.1:' + bridge.address().port + '/provider',
      bearer,
      keyRef: backend.settings.signingKeyRef,
      trustedBaseUrl: backend.settings.trustedBaseUrl,
      sampleIssues,
    };
    Object.values(fixture).forEach(remember);
    return {
      fixture,
      privacyValues,
      close,
      fault(name, value) {
        assert.ok(Object.hasOwn(faults, name));
        faults[name] = value;
      },
      async verify(expectedConsumed, expectedSamples = 0) {
        assert.equal(expectedSamples, sampleIssues ? 480 : 0);
        assert.equal(sampled.length, expectedSamples);
        let consumed = 0;
        const snapshots = new Map();
        for (const grant of [...grants, ...sampled]) {
          const record = await backend.base.backend.store.read(
            'magiclink.records.v1',
            grant.issueId,
          );
          assert.ok(['issued', 'consumed'].includes(record.state));
          snapshots.set(grant.issueId, record);
          if (record.state === 'consumed') consumed++;
        }
        const row = await backend.base.backend.app.sql.queryOne('main', {
          text: `SELECT COALESCE(sum((body::jsonb->>'count')::bigint),0)::text AS count FROM ${backend.base.backend.schema}.security_records WHERE namespace=:namespace`,
          bindings: { namespace: 'magiclink.quota.consume.v1' },
        });
        assert.equal(consumed, expectedConsumed);
        assert.equal(Number(row.count), expectedConsumed);
        assert.equal(state.committedBatches, expectedConsumed);
        let replayRejected = 0;
        if (sampleIssues) {
          assert.deepEqual(sampleCounts, [120, 120, 120, 120]);
          assert.equal(state.sampleIssueRequests, expectedSamples);
          assert.equal(sampleVerifications.size, expectedSamples);
          assert.equal(sampleAuthorizations.size, expectedSamples);
          assert.ok([...sampleVerifications.values()].every((count) => count === 1));
          assert.ok([...sampleAuthorizations.values()].every((count) => count === 1));
          assert.equal(
            new Set(sampled.map((grant) => grant.token.split('.')[2])).size,
            expectedSamples,
          );
          const issueQuota = await backend.base.backend.app.sql.queryOne('main', {
            text: `SELECT COALESCE(sum((body::jsonb->>'count')::bigint),0)::text AS count FROM ${backend.base.backend.schema}.security_records WHERE namespace=:namespace`,
            bindings: { namespace: 'magiclink.quota.issue.v1' },
          });
          assert.equal(Number(issueQuota.count), expectedConsumed);
          const quotas = await backend.base.backend.app.sql.query('main', {
            text: `SELECT namespace,body::jsonb->>'ownerKey' AS owner_key,sum((body::jsonb->>'count')::bigint)::text AS count FROM ${backend.base.backend.schema}.security_records WHERE namespace IN (:issue,:consume) GROUP BY namespace,body::jsonb->>'ownerKey' LIMIT 19`,
            bindings: { issue: 'magiclink.quota.issue.v1', consume: 'magiclink.quota.consume.v1' },
          });
          assert.equal(quotas.rows.length, 18);
          const sampledOwners = new Set(
            sampled.map((grant) => snapshots.get(grant.issueId).ownerKey),
          );
          assert.equal(sampledOwners.size, 8);
          for (const quota of quotas.rows)
            assert.equal(Number(quota.count), sampledOwners.has(quota.owner_key) ? 60 : 4);
          for (const grant of sampled) {
            await assert.rejects(
              backend.second.magic.consume(grant.token, { method: 'POST', purpose: 'login' }),
              { code: 'EK_MAGICLINK_REPLAY' },
            );
            assert.deepEqual(
              await backend.base.backend.store.read('magiclink.records.v1', grant.issueId),
              snapshots.get(grant.issueId),
            );
            replayRejected++;
          }
          const afterReplay = await backend.base.backend.app.sql.queryOne('main', {
            text: `SELECT COALESCE(sum((body::jsonb->>'count')::bigint),0)::text AS count FROM ${backend.base.backend.schema}.security_records WHERE namespace=:namespace`,
            bindings: { namespace: 'magiclink.quota.consume.v1' },
          });
          assert.equal(Number(afterReplay.count), expectedConsumed);
        }
        return {
          persistedConsumedLinks: consumed,
          persistedConsumeQuota: Number(row.count),
          committedAtomicBatches: state.committedBatches,
          ...(sampleIssues
            ? {
                sampledIssueRequests: state.sampleIssueRequests,
                independentlyCheckedSampleLinks: sampled.length,
                independentlyObservedHmacVerifications: sampleVerifications.size,
                independentlyObservedConsumeAuthorizations: sampleAuthorizations.size,
                uniqueNonceCount: expectedSamples,
                independentReplayRejections: replayRejected,
                sampledOwnerCount: sampleOwners.length,
                maximumIssueAndConsumePerSampleOwner: 60,
                configuredClaimsPerHour: 64,
                mailDeliveries: 0,
                parentIssuerResources: null,
                parentProviderResources: null,
                postgresServerResources: null,
              }
            : {}),
          releaseGate: false,
        };
      },
    };
  } catch (cause) {
    await close();
    throw cause;
  }
}
