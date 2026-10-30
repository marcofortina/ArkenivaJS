// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ldapSettings, ldapProjection, requireLdapProcessTreeResource } from '../ldap-workload.mjs';

test('LDAP comparison admits only a fixed verified owned endpoint before secret access', () => {
  for (const url of [
    'ldap://127.0.0.1:1',
    'ldaps://foreign.invalid:1',
    'ldaps://127.0.0.1:1/foreign',
    'ldaps://user:pass@127.0.0.1:1',
  ])
    assert.throws(() => ldapSettings({ url }));
});

test('LDAP entry rejects unsupported campaigns and unmarked smoke before private fixture or evidence access', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-ldap-entry-')),
    env = { ...process.env };
  delete env.ARKENIVA_LDAP_BENCHMARK_DISPOSABLE;
  delete env.ARKENIVA_LDAP_FIXTURE;
  try {
    for (const flag of ['--full', '--smoke']) {
      const output = join(directory, flag.slice(2));
      await assert.rejects(
        promisify(execFile)(
          process.execPath,
          [fileURLToPath(new URL('../ldap.mjs', import.meta.url)), flag, output],
          { env, timeout: 5000, maxBuffer: 1048576 },
        ),
        (error) =>
          error.code === 1 &&
          /full LDAP campaigns remain separate|explicitly disposable runner/.test(error.stderr),
      );
      await assert.rejects(access(output), { code: 'ENOENT' });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('LDAP comparison projection retains exact identity values and refuses hidden or ambiguous credential attributes', () => {
  const valid = {
    dn: 'uid=unit,dc=example',
    uid: 'unit',
    attributes: { uid: ['unit'], cn: ['Unit Fixture'] },
  };
  assert.deepEqual(ldapProjection(valid), valid);
  for (const changed of [
    null,
    { ...valid, password: 'not-a-permitted-projection' },
    { ...valid, attributes: { ...valid.attributes, userPassword: ['not-a-permitted-projection'] } },
    { ...valid, attributes: { uid: ['other'], cn: ['Unit Fixture'] } },
    { ...valid, attributes: { uid: ['unit', 'duplicate'], cn: ['Unit Fixture'] } },
    { ...valid, attributes: { uid: ['unit'], cn: [] } },
  ])
    assert.throws(() => ldapProjection(changed));
});

test('LDAP measurements refuse missing, partial or unfinished native-descendant accounting', () => {
  // Policy validation data only; these values are not measured resource evidence.
  const valid = {
    scope: 'whole-supervised-lifecycle',
    allChildrenWaited: true,
    remainingOwnedProcesses: 0,
    pythonObserverIncluded: false,
    externalServerResourcesIncluded: false,
    descendantDiscoveryQuality: {
      inaccessibleReads: 0,
      vanishedBeforeRead: 1,
      traversalLimitExceeded: false,
    },
    rssReadQuality: {
      inaccessibleReads: 0,
      vanishedBeforeRead: 1,
      allObservedReadsAccessible: true,
    },
    samplingRounds: 1,
    elapsedMs: 1,
    userCpuSeconds: 0,
    systemCpuSeconds: 0,
    maxSamplingGapMs: 1,
    largestSingleProcessRssBytes: 1,
    sampledSummedRssPeakBytes: 1,
    sampledLargestSingleRssBytes: 1,
    observedProcessCount: 2,
  };
  requireLdapProcessTreeResource(valid);
  for (const changed of [
    undefined,
    { ...valid, allChildrenWaited: false },
    { ...valid, remainingOwnedProcesses: 1 },
    { ...valid, scope: 'parent-only' },
    { ...valid, samplingRounds: 0 },
    { ...valid, userCpuSeconds: Number.NaN },
    {
      ...valid,
      descendantDiscoveryQuality: { ...valid.descendantDiscoveryQuality, inaccessibleReads: 1 },
    },
    {
      ...valid,
      descendantDiscoveryQuality: {
        ...valid.descendantDiscoveryQuality,
        traversalLimitExceeded: true,
      },
    },
    {
      ...valid,
      rssReadQuality: {
        ...valid.rssReadQuality,
        inaccessibleReads: 1,
        allObservedReadsAccessible: false,
      },
    },
  ])
    assert.throws(() => requireLdapProcessTreeResource(changed));
});

test('LDAP comparison passes explicit CA bytes through its private provider without ambient trust changes', async () => {
  const before = process.env.NODE_EXTRA_CA_CERTS,
    fixture = {
      url: 'ldaps://127.0.0.1:16389',
      bindDn: 'unit-dn',
      bindPassword: 'unit-value',
      caPem: 'unit-ca-bytes',
      baseDn: 'unit-base',
      groupBaseDn: 'unit-groups',
    },
    settings = ldapSettings(fixture);
  assert.equal(settings.tlsTrustBundleRef, 'trust');
  const value = await settings.secretProvider.get('trust');
  assert.deepEqual(value.bytes, Buffer.from(fixture.caPem));
  assert.equal(process.env.NODE_EXTRA_CA_CERTS, before);
});
