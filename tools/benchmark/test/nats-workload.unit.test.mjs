// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { natsConnection } from '../nats-workload.mjs';

test('NATS comparison rejects foreign destinations, missing mutual TLS and ambiguous namespaces before I/O', () => {
  for (const url of [
    'nats://user:pass@127.0.0.1:14223/',
    'tls://user:pass@foreign.invalid:14223/?prefix=owned.&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&caFile=/owned/ca',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.*&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&prefix=foreign.&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&caFile=relative&certFile=/owned/cert&keyFile=/owned/key',
    'tls://user:pass@127.0.0.1:14223/?prefix=owned.&caFile=/owned/ca&certFile=/owned/cert&keyFile=/owned/key&rejectUnauthorized=false',
  ])
    assert.throws(() => natsConnection({ url }));
});
