// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { etcdOptions, etcdKey, etcdBytes, etcdInteger } from '../../dist/common.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('EK-CONF-001 etcd captures millisecond options and rejects invalid objects, budgets and signals', () => {
  assert.equal(etcdOptions().timeoutMs, 15_000);
  assert.equal(etcdOptions(undefined, 5000).timeoutMs, 5000);
  const signal = new AbortController().signal,
    input = { timeoutMs: 20, signal };
  const captured = etcdOptions(input);
  input.timeoutMs = 50;
  assert.deepEqual(captured, { timeoutMs: 20, signal });
  assert.equal(
    etcdOptions({ timeoutMs: Number.MAX_SAFE_INTEGER }).timeoutMs,
    Number.MAX_SAFE_INTEGER,
  );
  for (const input of [
    null,
    [],
    1,
    { signal: {} },
    ...[0, -1, 1.5, NaN, Infinity, '1'].map((timeoutMs) => ({ timeoutMs })),
  ])
    assert.throws(() => etcdOptions(input as never), code('EK_CONFIG_INVALID'));
  assert.throws(() => etcdOptions({ signal: AbortSignal.abort('Stopped') }), code('EK_ABORTED'));
});

test('EK-DB-002 etcd keys preserve exact UTF-8 namespaces and raw bytes are cloned without text conversion', () => {
  assert.equal(etcdKey('/../value', '/tenant/'), '/tenant//../value');
  assert.equal(etcdKey('', '/tenant/', true), '/tenant/');
  assert.equal(etcdKey('\uFEFFkey', ''), '\uFEFFkey');
  assert.equal(etcdKey('😀'.repeat(1024), '').length, 2048);
  for (const value of ['', '\0key', 'line\rkey', 'line\nkey', '\ud800', '😀'.repeat(1025), null])
    assert.throws(() => etcdKey(value as string, ''), code('EK_CONFIG_INVALID'));
  const source = Uint8Array.from([0, 255, 128]),
    snapshot = etcdBytes(source);
  source.fill(1);
  assert.deepEqual(snapshot, Buffer.from([0, 255, 128]));
  assert.equal(etcdBytes(new Uint8Array()).byteLength, 0);
  for (const value of [null, 'text', [], new Uint8Array(1_048_577)])
    assert.throws(() => etcdBytes(value as never), code('EK_CONFIG_INVALID'));
});

test('EK-DB-002 etcd decodes exact positive int64 text and never rounds through JavaScript numbers', () => {
  assert.equal(etcdInteger('9007199254740993'), 9007199254740993n);
  assert.equal(etcdInteger('9223372036854775807'), 9_223_372_036_854_775_807n);
  assert.equal(etcdInteger('0', true), 0n);
  for (const value of [
    '0',
    '',
    '01',
    '-1',
    '1.5',
    '1\n',
    '9223372036854775808',
    '12345678901234567890',
    1,
    null,
  ])
    assert.throws(() => etcdInteger(value), code('EK_BACKEND_UNAVAILABLE'));
});
