// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { checkServerIdentity } from 'node:tls';
import { Client, EqualityFilter, InvalidCredentialsError } from 'ldapts';

export function ldapSettings(fixture) {
  const url = new URL(fixture.url);
  assert.equal(url.protocol, 'ldaps:');
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.href, fixture.url);
  assert.equal(url.username + url.password + url.search + url.hash, '');
  assert.ok(url.port);
  assert.equal(url.pathname, '');
  const values = new Map([
    ['bind-dn', fixture.bindDn],
    ['bind-password', fixture.bindPassword],
    ['trust', fixture.caPem],
  ]);
  return {
    url: fixture.url,
    baseDn: fixture.baseDn,
    groupSearchBaseDn: fixture.groupBaseDn,
    userFilterTemplate: '(uid={username})',
    serviceBindDnRef: 'bind-dn',
    serviceBindPasswordRef: 'bind-password',
    tlsTrustBundleRef: 'trust',
    environment: 'test',
    allowedAttributes: ['uid', 'cn'],
    timeoutMs: 5000,
    secretProvider: {
      usage: 'test-only',
      async get(reference) {
        assert.ok(values.has(reference));
        return { bytes: Buffer.from(values.get(reference)), keyVersion: 'one' };
      },
    },
  };
}

/** Every native operation uses fresh verified TLS clients and closes them after acknowledged work. */
export function nativeLdap(fixture) {
  ldapSettings(fixture);
  const connect = async (dn, password, work) => {
    const client = new Client({
      url: fixture.url,
      timeout: 5000,
      connectTimeout: 5000,
      tlsOptions: {
        ca: fixture.caPem,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        checkServerIdentity: (_name, certificate) => checkServerIdentity('127.0.0.1', certificate),
      },
    });
    try {
      await client.bind(dn, password);
      return await work(client);
    } finally {
      await client.unbind();
    }
  };
  const service = (work) => connect(fixture.bindDn, fixture.bindPassword, work);
  const find = async (client, username) => {
    const result = await client.search(fixture.baseDn, {
      scope: 'sub',
      filter: new EqualityFilter({ attribute: 'uid', value: username }),
      attributes: ['uid', 'cn'],
      sizeLimit: 2,
      paged: { pageSize: 2 },
    });
    assert.ok(result.searchEntries.length <= 1);
    if (!result.searchEntries.length) return null;
    const entry = result.searchEntries[0],
      attributes = Object.create(null);
    for (const name of ['uid', 'cn']) {
      const value = entry[name];
      const values = Array.isArray(value) ? value : [value];
      assert.ok(values.every((item) => typeof item === 'string'));
      attributes[name] = values;
    }
    return { dn: entry.dn, uid: attributes.uid[0], attributes };
  };
  return {
    ping: () => service(async () => true),
    findUser: ({ username }) => service((client) => find(client, username)),
    verifyCredentials: ({ username }, password) =>
      service(async (client) => {
        const user = await find(client, username);
        if (!user) return false;
        try {
          return await connect(user.dn, password, async () => true);
        } catch (error) {
          if (error instanceof InvalidCredentialsError) return false;
          throw error;
        }
      }),
  };
}

const observations = new WeakMap();

/** Keep directory results private and verify the same bounded projection in both paths. */
export function ldapProjection(user) {
  assert.ok(user && typeof user === 'object');
  assert.deepEqual(Object.keys(user).sort(), ['attributes', 'dn', 'uid']);
  assert.equal(typeof user.dn, 'string');
  assert.ok(user.dn.length > 0 && user.dn.length <= 2048);
  assert.equal(typeof user.uid, 'string');
  assert.ok(user.uid.length > 0 && user.uid.length <= 16384);
  assert.deepEqual(Object.keys(user.attributes).sort(), ['cn', 'uid']);
  for (const values of Object.values(user.attributes)) {
    assert.ok(Array.isArray(values) && values.length > 0 && values.length <= 128);
    assert.ok(
      values.every(
        (value) => typeof value === 'string' && value.length > 0 && value.length <= 16384,
      ),
    );
  }
  assert.deepEqual([...user.attributes.uid], [user.uid]);
  return JSON.parse(JSON.stringify(user));
}

/** Refuse missing or partial descendant observations instead of falling back to parent-only CPU. */
export function requireLdapProcessTreeResource(resource) {
  assert.ok(resource, 'LDAP sampling requires complete native child process accounting');
  assert.equal(resource.scope, 'whole-supervised-lifecycle');
  assert.equal(resource.allChildrenWaited, true);
  assert.equal(resource.remainingOwnedProcesses, 0);
  assert.equal(resource.pythonObserverIncluded, false);
  assert.equal(resource.externalServerResourcesIncluded, false);
  assert.equal(resource.descendantDiscoveryQuality.inaccessibleReads, 0);
  assert.equal(resource.descendantDiscoveryQuality.traversalLimitExceeded, false);
  assert.equal(resource.rssReadQuality.inaccessibleReads, 0);
  assert.equal(resource.rssReadQuality.allObservedReadsAccessible, true);
  assert.ok(
    Number.isSafeInteger(resource.samplingRounds) &&
      resource.samplingRounds > 0 &&
      resource.samplingRounds <= 10000,
  );
  for (const key of [
    'elapsedMs',
    'userCpuSeconds',
    'systemCpuSeconds',
    'maxSamplingGapMs',
    'largestSingleProcessRssBytes',
    'sampledSummedRssPeakBytes',
    'sampledLargestSingleRssBytes',
  ])
    assert.ok(Number.isFinite(resource[key]) && resource[key] >= 0);
  for (const value of [
    resource.descendantDiscoveryQuality.vanishedBeforeRead,
    resource.rssReadQuality.vanishedBeforeRead,
  ])
    assert.ok(Number.isSafeInteger(value) && value >= 0);
  assert.ok(
    Number.isSafeInteger(resource.observedProcessCount) && resource.observedProcessCount >= 2,
  );
}

export async function verifyLdap(service, fixture) {
  assert.equal(await service.ping(), true);
  const found = await service.findUser({ username: 'alice' });
  assert.ok(found);
  assert.equal(found.uid, 'alice');
  const expected = await nativeLdap(fixture).findUser({ username: 'alice' });
  assert.deepEqual(ldapProjection(found), ldapProjection(expected));
  assert.deepEqual([...found.attributes.uid], ['alice']);
  assert.ok(found.attributes.cn.length > 0);
  assert.equal(await service.findUser({ username: 'owned-absent-comparison-user' }), null);
  assert.equal(await service.findUser({ username: '*)(uid=*)' }), null);
  assert.equal(await service.verifyCredentials({ username: 'alice' }, fixture.userPassword), true);
  assert.equal(
    await service.verifyCredentials({ username: 'alice' }, fixture.userPassword + '-incorrect'),
    false,
  );
  observations.set(service, {
    expected: ldapProjection(expected),
    callbacks: 0,
    completed: 0,
    active: 0,
    peakActive: 0,
    independentReadbacks: 0,
  });
  return {
    verifiedServiceBind: true,
    actualUserFound: true,
    absentUser: true,
    filterInjectionAbsent: true,
    correctPassword: true,
    incorrectPasswordRejected: true,
  };
}

/** Each callback awaits one actual verified service bind and exact projected user search. */
export function ldapWorkload(service) {
  const state = observations.get(service);
  assert.ok(state, 'LDAP corpus verification must precede workload execution');
  return {
    'verified-service-bind-and-user-search': async () => {
      assert.equal(state.active, 0);
      state.callbacks++;
      state.active++;
      state.peakActive = Math.max(state.peakActive, state.active);
      try {
        const found = await service.findUser({ username: 'alice' });
        assert.deepEqual(ldapProjection(found), state.expected);
        state.completed++;
        return true;
      } finally {
        state.active--;
      }
    },
  };
}

/** A fresh independent native LDAPS readback remains outside the timed samples. */
export async function ldapObservations(service, { fixture, measure, records }) {
  const state = observations.get(service);
  assert.ok(state, 'LDAP corpus verification must precede completion');
  assert.equal(state.callbacks, state.completed);
  assert.equal(state.active, 0);
  assert.ok(state.peakActive <= 1);
  if (measure) {
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'verified-service-bind-and-user-search');
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, record.sampleCount);
    assert.ok(record.rawLatency.values.every((value) => Number.isFinite(value) && value >= 0));
    assert.equal(state.callbacks, record.sampleCount + record.warmupIterations);
    const independent = await nativeLdap(fixture).findUser({ username: 'alice' });
    assert.deepEqual(ldapProjection(independent), state.expected);
    state.independentReadbacks++;
    assert.equal(state.independentReadbacks, 1);
  } else assert.equal(records.length, 0);
  return {
    actualSearchCallbacks: state.callbacks,
    successfulProjectedSearches: state.completed,
    activeSearchCallbacks: state.active,
    peakConcurrentCallbacks: state.peakActive,
    independentVerifiedReadbacks: state.independentReadbacks,
  };
}
