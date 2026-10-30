// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import {
  connectEtcd,
  etcdConnection,
  cleanupEtcd,
  selectEtcdProfile,
  verifyEtcdCasReadback,
  etcdIterations,
  etcdWarmupIterations,
} from './etcd-workload.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or --smoke with a fresh absolute external report directory',
);
assert.equal(
  process.env.ARKENIVA_ETCD_DISPOSABLE,
  '1',
  'Use only the explicitly owned disposable etcd fixture',
);
const profileNamespaces = Array.from(
    { length: 4 },
    () => 'comparison_' + randomBytes(16).toString('hex') + '/',
  ),
  fixture = {
    url: process.env.ARKENIVA_ETCD_URL,
    namespace: profileNamespaces[0],
    profileNamespaces,
  };
const config = etcdConnection(fixture),
  profiles = ['BASELINE', 'FRAMEWORK', 'STANDARD', 'DETAILED'].map((mode) => ({
    mode,
    fixture: selectEtcdProfile(fixture, mode),
  })),
  observer = await connectEtcd(fixture, 65536),
  owned = [];
try {
  for (const profile of profiles) {
    const physical = etcdConnection(profile.fixture).physical;
    assert.equal((await observer.getAll().prefix(physical).limit(1).exec()).kvs.length, 0);
    owned.push(profile.fixture);
  }
  const report = await runPureComparison(
    {
      scenarioId: 'etcd-native-bytes-revisions-cas-watch-and-lease-verification',
      fixture,
      privacyValues: [
        fixture.url,
        ...profileNamespaces,
        config.prefix,
        ...['sslca', 'sslcert', 'sslkey'].map((key) => config.url.searchParams.get(key)),
        'localhost',
        '127.0.0.1',
      ],
      privacyField: 'inputOccurrences',
      worker: new URL('./etcd-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'etcd3@1.1.2',
        operations: ['get', 'put', 'delete', 'compareAndSwap', 'watch', 'grantLease'],
        samplingSupported: true,
        measuredOperation: 'fresh-key CAS with expectedRevision zero',
        samplesPerProfile: args[0] === '--smoke' ? etcdIterations : 0,
        warmupCreatesPerProfile: args[0] === '--smoke' ? etcdWarmupIterations : 0,
        concurrency: 1,
      },
      observationCoverage:
        'Actual mTLS etcd profiles preserve the existing bytes/revisions/CAS/watch/lease verification. Optional smoke times one acknowledged fresh-key CAS per callback; one stale create fails after timing. The independent parent native client reads every retained key with a bounded range and validates exact bytes, version one and ordered bigint modification revisions before scoped cleanup. Actual SDK exports exclude fixture input.',
      limitations:
        'Valid fixed corpus on an owned single-member server. Native baseline omits portable admission, deadlines/cancellation ownership, stream gap handling and lease ownership policy. CAS-create samples do not measure update-CAS, watch/lease throughput, compaction, partition or multi-member behavior. Child process resources exclude the separate parent observer and etcd server, which remain unknown. No complete resource parity, calibrated budget, five repetitions, one-hour soak or full campaign acceptance. A prefix is not application tenant authorization.',
    },
    args,
  );
  const readbacks = [];
  if (args[0] === '--smoke')
    for (const row of report.records) {
      const selected = profiles.find((profile) => profile.mode === row.mode);
      assert.ok(selected);
      assert.equal(
        row.completion.acknowledgedCreates,
        row.completion.sampledCreates + row.completion.warmupCreates,
      );
      assert.equal(row.completion.staleCasRejections, 1);
      readbacks.push({
        mode: row.mode,
        ...(await verifyEtcdCasReadback(
          observer,
          selected.fixture,
          row.completion.acknowledgedCreates,
        )),
      });
    }
  for (const profile of profiles) {
    await cleanupEtcd(observer, profile.fixture);
    assert.equal(
      (await observer.getAll().prefix(etcdConnection(profile.fixture).physical).limit(1).exec()).kvs
        .length,
      0,
    );
  }
  const observation = {
    ownedKeysRemaining: 0,
    ...(args[0] === '--smoke'
      ? {
          acknowledgedCasCreates: report.records.reduce(
            (sum, row) => sum + row.completion.acknowledgedCreates,
            0,
          ),
          staleCasRejections: report.records.reduce(
            (sum, row) => sum + row.completion.staleCasRejections,
            0,
          ),
          independentReadbackMatches: readbacks.reduce(
            (sum, row) => sum + row.independentlyVerifiedKeys,
            0,
          ),
          profileReadbacks: readbacks,
          parentObserverResources: null,
          serverResources: null,
        }
      : {}),
    releaseGate: false,
  };
  const encoded = JSON.stringify(observation, null, 2) + '\n';
  for (const value of [fixture.url, ...profileNamespaces, config.prefix, 'localhost', '127.0.0.1'])
    assert.equal(encoded.includes(value), false);
  await writeFile(resolve(args[1], 'protocol-observation.json'), encoded, {
    mode: 0o600,
    flag: 'wx',
  });
} finally {
  try {
    const cleanup = await Promise.allSettled(
      owned.map((profile) => cleanupEtcd(observer, profile)),
    );
    assert.ok(
      cleanup.every((result) => result.status === 'fulfilled'),
      'Owned etcd namespace cleanup failed',
    );
  } finally {
    observer.close();
  }
}
