// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import { capture, remotePath, within } from '../../dist/settings.js';
import type { SftpPluginSettings } from '../../dist/contracts.js';

const settings = (): SftpPluginSettings => ({
  connections: [
    {
      name: 'partner',
      host: 'example.test',
      port: 22,
      username: 'transfer',
      privateKeyRef: 'partner-key',
      knownHostSha256: ['SHA256:' + Buffer.alloc(32, 7).toString('base64').replace(/=+$/, '')],
      allowedRemoteRoots: ['/incoming'],
    },
  ],
  secretProvider: {
    async get() {
      throw new Error('No provider I/O is permitted during capture');
    },
  },
  policy: { maxConcurrent: 2, timeoutMs: 5000 },
});
test('SFTP captures approved profiles, host pins, roots and literal command templates without I/O', () => {
  const original = settings(),
    captured = capture({
      ...original,
      allowedCommands: { report: { executable: '/usr/bin/printf', arguments: ['%s', '{value}'] } },
    });
  assert.equal(captured.connections[0]!.host, 'example.test');
  assert.equal(captured.commands.report!.parameters[0], 'value');
  assert.ok(Object.isFrozen(captured));
  assert.ok(Object.isFrozen(captured.connections[0]));
});
test('SFTP refuses malformed trust policy, unlimited timeouts, accessors and unsafe command declarations', () => {
  for (const input of [
    undefined,
    {},
    { ...settings(), connections: [] },
    { ...settings(), policy: { maxConcurrent: 1, timeoutMs: 0 } },
    { ...settings(), connections: [{ ...settings().connections[0]!, knownHostSha256: [] }] },
    { ...settings(), connections: [{ ...settings().connections[0]!, host: 'ssh://untrusted' }] },
    { ...settings(), allowedCommands: { bad: { executable: '/bin/sh;touch', arguments: [] } } },
    Object.defineProperty({}, 'connections', {
      enumerable: true,
      get() {
        throw new Error('Accessor must not execute');
      },
    }),
  ])
    assert.throws(
      () => capture(input as SftpPluginSettings),
      (error) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
    );
});
test('Remote paths are canonical POSIX paths and membership checks never accept prefix lookalikes', () => {
  assert.equal(remotePath('/incoming/sub/../file'), '/incoming/file');
  assert.ok(within('/incoming/file', '/incoming'));
  assert.equal(within('/incoming-escape/file', '/incoming'), false);
  for (const value of ['relative', '/incoming\\escape', '/incoming\nfile'])
    assert.throws(() => remotePath(value));
});
