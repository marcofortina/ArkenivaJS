// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sftpSettings } from '../sftp-workload.mjs';

test('SFTP comparison rejects foreign endpoints and unowned paths before decoding a private key', () => {
  const base = {
    host: '127.0.0.1',
    port: 1,
    root: '/home/transfer/data',
    fileStem: 'owned-comparison-' + 'a'.repeat(32),
  };
  for (const change of [
    { host: 'foreign.invalid' },
    { port: 0 },
    { port: 1.5 },
    { port: 65536 },
    { root: '/foreign' },
    { fileStem: '../foreign' },
  ])
    assert.throws(() => sftpSettings({ ...base, ...change }));
});
