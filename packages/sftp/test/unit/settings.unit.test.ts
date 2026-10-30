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

test('SFTP captures the original secret method and receiver without evaluating callable metadata', async () => {
  let effects = 0,
    calls = 0;
  const provider = {
    async get(this: unknown, reference: string) {
      assert.equal(this, provider);
      assert.equal(reference, 'owned');
      calls++;
      return { bytes: Buffer.from('disposable'), keyVersion: 'one' };
    },
  };
  for (const field of ['name', 'length', 'bind'])
    Object.defineProperty(provider.get, field, {
      get() {
        effects++;
        return field === 'length' ? 1 : 'unused';
      },
    });
  const captured = capture({ ...settings(), secretProvider: provider });
  assert.equal(effects, 0);
  assert.equal(calls, 0);
  provider.get = async () => {
    throw new Error('Later method replacement must not run');
  };
  assert.equal((await captured.getSecret('owned')).keyVersion, 'one');
  assert.equal(calls, 1);
  assert.equal(effects, 0);
});
test('SFTP rejects proxy secret authorities, callbacks and hidden usage classification without evaluating traps', () => {
  let effects = 0;
  const target = settings().secretProvider;
  const trap = () => {
    effects++;
    throw new Error('Provider proxy traps must not execute');
  };
  const proxies = [
    new Proxy(target, { getPrototypeOf: trap, getOwnPropertyDescriptor: trap, get: trap }),
    { get: new Proxy(target.get, { apply: trap, get: trap, getOwnPropertyDescriptor: trap }) },
    Object.assign(
      Object.create(new Proxy({}, { getOwnPropertyDescriptor: trap, getPrototypeOf: trap })),
      { get: target.get },
    ) as typeof target,
  ];
  for (const secretProvider of proxies)
    assert.throws(
      () => capture({ ...settings(), secretProvider }),
      (error: unknown) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
    );
  assert.equal(effects, 0);
  let prototype: object = { usage: 'test-only' };
  for (let depth = 0; depth < 65; depth++) prototype = Object.create(prototype) as object;
  const provider = Object.assign(Object.create(prototype), { get: target.get }) as typeof target;
  assert.throws(
    () => capture({ ...settings(), secretProvider: provider }),
    (error: unknown) => error instanceof KitError && error.code === 'EK_CONFIG_INVALID',
  );
});
