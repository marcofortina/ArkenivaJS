// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runProxyExample } from '../../dist/run.js';

test('Public installed artifacts run an actual HTTPS proxy with native streaming and explicit certificate trust', async () => {
  const result = await runProxyExample();
  assert.equal(result.untrustedCertificateRejected, true);
  assert.equal(result.rewritten, true);
  assert.equal(result.identityHeadersStripped, true);
  assert.equal(result.bytes, 65536);
  assert.equal(result.unsafePathRejected, true);
  assert.equal(result.stats.forwardedRequests, 1);
  assert.equal(result.stats.rejectedRequests, 1);
  assert.equal(result.stats.observedRequestBytes, 65536);
  assert.ok(result.stats.observedResponseBytes > 0);
});
