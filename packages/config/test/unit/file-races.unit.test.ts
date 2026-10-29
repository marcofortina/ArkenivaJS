// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createConfig } from '@arkenivajs/config';

const schema = {
  type: 'object',
  additionalProperties: false,
  properties: { count: { type: 'integer' } },
};

test('Configuration rejects a file replaced by an outside-workspace symlink after canonicalization', async (context) => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkeniva-config-replacement-'));
  const workspace = join(directory, 'workspace'),
    target = join(workspace, 'app.yaml'),
    outside = join(directory, 'outside.yaml');
  await fs.mkdir(workspace);
  await fs.writeFile(target, 'count: 1\n');
  await fs.writeFile(outside, 'count: 99\n');
  const original = fs.realpath;
  let replaced = false;
  context.mock.method(fs, 'realpath', async (path: string) => {
    const resolved = await original(path);
    if (path === target && !replaced) {
      replaced = true;
      await fs.unlink(target);
      await fs.symlink(outside, target);
    }
    return resolved;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(
      createConfig({ schema, workspace, yamlFile: 'app.yaml', environment: {} }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(replaced, true);
  } finally {
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('Configuration rejects replacement between metadata checks and opening the descriptor', async (context) => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkeniva-config-open-race-'));
  const workspace = join(directory, 'workspace'),
    target = join(workspace, 'app.yaml'),
    outside = join(directory, 'outside.yaml');
  await fs.mkdir(workspace);
  await fs.writeFile(target, 'count: 1\n');
  await fs.writeFile(outside, 'count: 99\n');
  const original = fs.open;
  let replaced = false;
  context.mock.method(fs, 'open', async (path: string, flags: number) => {
    if (path === target && !replaced) {
      replaced = true;
      await fs.unlink(target);
      await fs.symlink(outside, target);
    }
    return original(path, flags);
  });
  try {
    await assert.rejects(
      createConfig({ schema, workspace, yamlFile: 'app.yaml', environment: {} }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(replaced, true);
  } finally {
    context.mock.restoreAll();
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('Configuration rejects growth after descriptor validation without allocating a larger read buffer', async (context) => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkeniva-config-growth-'));
  const target = join(directory, 'app.yaml');
  await fs.writeFile(target, 'count: 1\n');
  const control = await fs.open(target, 'r+'),
    prototype = Object.getPrototypeOf(control) as FileHandle;
  const stat = prototype.stat,
    read = prototype.read,
    buffers: number[] = [];
  let grew = false;
  context.mock.method(
    prototype,
    'stat',
    async function (this: FileHandle, options: Parameters<FileHandle['stat']>[0]) {
      const snapshot = await stat.call(this, options);
      if (this.fd !== control.fd && !grew) {
        grew = true;
        await control.truncate(2097152);
      }
      return snapshot;
    },
  );
  context.mock.method(prototype, 'read', function (this: FileHandle, ...args: unknown[]) {
    if (args[0] instanceof Uint8Array) buffers.push(args[0].byteLength);
    return Reflect.apply(read, this, args) as ReturnType<FileHandle['read']>;
  });
  try {
    await assert.rejects(
      createConfig({ schema, workspace: directory, yamlFile: 'app.yaml', environment: {} }),
      { code: 'EK_CONFIG_INVALID' },
    );
    assert.equal(grew, true);
    assert.ok(buffers.length > 0);
    assert.ok(buffers.every((length) => length <= 1048576));
  } finally {
    context.mock.restoreAll();
    await control.close();
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('Configuration preserves valid in-workspace aliases and BOM while rejecting oversized or invalid UTF-8 files', async () => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkeniva-config-file-policy-'));
  const target = join(directory, 'app.yaml');
  try {
    await fs.writeFile(target, '\uFEFFcount: 4\n');
    await fs.symlink(target, join(directory, 'alias.yaml'));
    const options = { schema, workspace: directory, yamlFile: 'alias.yaml', environment: {} };
    assert.equal((await createConfig(options)).get('count'), 4);
    const header = 'count: 4\n#';
    await fs.writeFile(target, header + 'x'.repeat(1048576 - Buffer.byteLength(header)));
    assert.equal((await createConfig(options)).get('count'), 4);
    await fs.appendFile(target, 'x');
    await assert.rejects(createConfig(options), { code: 'EK_CONFIG_INVALID' });
    await fs.writeFile(target, Buffer.from([0xff]));
    await assert.rejects(createConfig(options), { code: 'EK_CONFIG_INVALID' });
    await assert.rejects(createConfig({ ...options, yamlFile: '.' }), {
      code: 'EK_CONFIG_INVALID',
    });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
});

test('Concurrent configuration loads own distinct descriptors and cancellation allocates no late file handle', async (context) => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkeniva-config-owned-files-'));
  await fs.writeFile(join(directory, 'one.yaml'), 'count: 1\n');
  await fs.writeFile(join(directory, 'two.yaml'), 'count: 2\n');
  const original = fs.open,
    handles: FileHandle[] = [];
  context.mock.method(fs, 'open', async (path: string, flags: number) => {
    const file = await original(path, flags);
    handles.push(file);
    return file;
  });
  const options = {
    schema,
    workspace: directory,
    environment: {},
    signal: new AbortController().signal,
  };
  try {
    const values = await Promise.all(
      ['one.yaml', 'two.yaml', 'one.yaml'].map((yamlFile) =>
        createConfig({ ...options, yamlFile }),
      ),
    );
    assert.deepEqual(
      values.map((config) => config.get('count')),
      [1, 2, 1],
    );
    assert.notEqual(values[0], values[2]);
    assert.equal(handles.length, 3);
    assert.ok(handles.every((file) => file.fd === -1));
    await assert.rejects(
      createConfig({ ...options, yamlFile: 'one.yaml', signal: AbortSignal.abort() }),
      { code: 'EK_ABORTED' },
    );
    assert.equal(handles.length, 3);
  } finally {
    context.mock.restoreAll();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
