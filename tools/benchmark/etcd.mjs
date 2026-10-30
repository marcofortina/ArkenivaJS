// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { connectEtcd, etcdConnection, cleanupEtcd } from './etcd-workload.mjs';
import { runPureComparison } from './pure-comparison.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && args[0] === '--verify',
  'Use --verify with a fresh absolute external report directory; complete etcd server resource sampling remains separate',
);
assert.equal(
  process.env.ARKENIVA_ETCD_DISPOSABLE,
  '1',
  'Use only the explicitly owned disposable etcd fixture',
);
const fixture = {
  url: process.env.ARKENIVA_ETCD_URL,
  namespace: 'comparison_' + randomBytes(16).toString('hex') + '/',
};
const config = etcdConnection(fixture),
  observer = await connectEtcd(fixture);
let owned = false;
try {
  assert.equal((await observer.getAll().prefix(config.physical).exec()).kvs.length, 0);
  owned = true;
  await runPureComparison(
    {
      scenarioId: 'etcd-native-bytes-revisions-cas-watch-and-lease-verification',
      fixture,
      privacyValues: [
        ...Object.values(fixture),
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
        samplingSupported: false,
      },
      observationCoverage:
        'Actual mTLS etcd profiles preserve binary values, bigint revisions/version, one concurrent CAS winner, three ordered watch events and granted/revoked native leases. Independent readback and scoped cleanup accompany actual SDK privacy checks.',
      limitations:
        'Valid fixed corpus on an owned single-member server. Native baseline omits portable admission, deadlines/cancellation ownership, stream gap handling and lease ownership policy. No compaction, partition, failover, lease-expiry duration, complete server resources or full campaign acceptance. A prefix is not application tenant authorization.',
    },
    args,
  );
  assert.equal((await observer.getAll().prefix(config.physical).exec()).kvs.length, 0);
  await writeFile(
    resolve(args[1], 'protocol-observation.json'),
    JSON.stringify({ ownedKeysRemaining: 0, releaseGate: false }, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
} finally {
  try {
    if (owned) await cleanupEtcd(observer, fixture);
  } finally {
    observer.close();
  }
}
