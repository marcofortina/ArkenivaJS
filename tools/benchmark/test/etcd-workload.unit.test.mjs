// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { etcdConnection } from '../etcd-workload.mjs';

test('Owned etcd comparison rejects foreign origins, TLS bypasses and unrelated namespaces before I/O', () => {
  const url = new URL('https://localhost:12379');
  for (const key of ['sslca', 'sslcert', 'sslkey']) url.searchParams.set(key, '/private/' + key);
  url.searchParams.set('prefix', '/arkeniva_test_' + 'a'.repeat(24) + '/');
  const fixture = { url: url.href, namespace: 'comparison_' + 'b'.repeat(32) + '/' };
  assert.ok(etcdConnection(fixture));
  for (const change of [
    (u) => {
      u.hostname = 'foreign.invalid';
    },
    (u) => {
      u.protocol = 'http:';
    },
    (u) => {
      u.searchParams.set('sslkey', 'relative');
    },
    (u) => {
      u.searchParams.set('tlsInsecure', 'true');
    },
    (u) => {
      u.searchParams.append('sslca', '/another');
    },
    (u) => {
      u.searchParams.set('prefix', '/unrelated/');
    },
  ]) {
    const changed = new URL(url);
    change(changed);
    assert.throws(() => etcdConnection({ ...fixture, url: changed.href }));
  }
  assert.throws(() => etcdConnection({ ...fixture, namespace: '/unrelated/' }));
});
