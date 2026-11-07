// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertXmlAssets, xmlSchemaArtifacts } from '../xml-xsd.mjs';

async function fixture(context) {
  const directory = await fs.mkdtemp(join(os.tmpdir(), 'arkenivajs-xml-assets-')),
    schemas = {};
  for (const [id, artifact] of Object.entries(xmlSchemaArtifacts)) {
    const bytes = await fs.readFile(
      new URL('../../../examples/xml/test/fixtures/' + artifact.name, import.meta.url),
    );
    schemas[id] = join(directory, artifact.name);
    await fs.writeFile(schemas[id], bytes, { mode: 0o600 });
  }
  // Model namespace interface observation only; these unit tests do not claim network isolation.
  context.mock.method(os, 'networkInterfaces', () => ({ lo: [] }));
  syncBuiltinESMExports();
  context.after(async () => {
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await fs.rm(directory, { recursive: true, force: true });
  });
  return {
    directory,
    configuration: { namespaceInode: (await fs.stat('/proc/self/ns/net')).ino, schemas },
  };
}

test('XML benchmark assets accept the exact private schema bytes through closed bounded descriptors', async (context) => {
  const { configuration } = await fixture(context),
    open = fs.open,
    descriptors = [],
    reads = [];
  context.mock.method(fs, 'open', async (path, flags) => {
    const file = await open(path, flags),
      read = file.read;
    descriptors.push(file);
    context.mock.method(file, 'read', function (...args) {
      reads.push(args[0].byteLength);
      return Reflect.apply(read, this, args);
    });
    return file;
  });
  syncBuiltinESMExports();
  await assertXmlAssets(configuration);
  assert.equal(descriptors.length, 2);
  assert.ok(descriptors.every((file) => file.fd === -1));
  assert.ok(reads.length >= 4);
  assert.ok(reads.every((length) => length > 0 && length <= 4096));
});

test('XML benchmark asset replacement is rejected before reading a different regular inode', async (context) => {
  const { directory, configuration } = await fixture(context),
    target = configuration.schemas.invoice,
    replacement = join(directory, 'replacement.xsd'),
    bytes = await fs.readFile(target),
    realpath = fs.realpath,
    readFile = fs.readFile,
    open = fs.open;
  await fs.writeFile(replacement, bytes, { mode: 0o600 });
  assert.notEqual((await fs.lstat(target)).ino, (await fs.lstat(replacement)).ino);
  let replaced = false,
    pathReads = 0,
    descriptorReads = 0;
  const descriptors = [];
  context.mock.method(fs, 'realpath', async (path, options) => {
    const result = await realpath(path, options);
    if (path === target && !replaced) {
      replaced = true;
      await fs.rename(replacement, target);
    }
    return result;
  });
  context.mock.method(fs, 'readFile', async (path, options) => {
    if (path === target) pathReads++;
    return readFile(path, options);
  });
  context.mock.method(fs, 'open', async (path, flags) => {
    const file = await open(path, flags),
      read = file.read;
    descriptors.push(file);
    context.mock.method(file, 'read', function (...args) {
      descriptorReads++;
      return Reflect.apply(read, this, args);
    });
    return file;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(assertXmlAssets(configuration), /The private XML schema artifact changed/);
    assert.equal(replaced, true);
    assert.equal(pathReads, 0);
    assert.equal(descriptorReads, 0);
    assert.equal(descriptors.length, 1);
    assert.equal(descriptors[0].fd, -1);
    assert.deepEqual(await readFile(target), bytes);
  } finally {
    context.diagnostic(JSON.stringify({ replaced, pathReads, descriptorReads }));
    await Promise.all(descriptors.map((file) => file.close()));
  }
});

test('XML benchmark assets reject growth during descriptor reads and close the captured file', async (context) => {
  const { configuration } = await fixture(context),
    target = configuration.schemas.invoice,
    open = fs.open;
  let grew = false;
  const descriptors = [];
  context.mock.method(fs, 'open', async (path, flags) => {
    const file = await open(path, flags),
      read = file.read;
    descriptors.push(file);
    context.mock.method(file, 'read', async function (...args) {
      const result = await Reflect.apply(read, this, args);
      if (path === target && !grew) {
        grew = true;
        await fs.appendFile(target, '\n');
      }
      return result;
    });
    return file;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(assertXmlAssets(configuration), /The private XML schema artifact changed/);
    assert.equal(grew, true);
    assert.equal(descriptors.length, 1);
    assert.equal(descriptors[0].fd, -1);
  } finally {
    await Promise.all(descriptors.map((file) => file.close()));
  }
});

test('XML benchmark assets retain pinned digest rejection for stable private files', async (context) => {
  const { configuration } = await fixture(context),
    target = configuration.schemas.invoice,
    bytes = await fs.readFile(target);
  bytes[bytes.indexOf(Buffer.from('invoice'))] = 'I'.charCodeAt(0);
  await fs.writeFile(target, bytes, { mode: 0o600 });
  await assert.rejects(assertXmlAssets(configuration), /The private XML schema artifact changed/);
});

test('XML benchmark assets reject metadata changes after the pinned bytes have been read', async (context) => {
  const { configuration } = await fixture(context),
    target = configuration.schemas.invoice,
    open = fs.open;
  let changed = false;
  const descriptors = [];
  assert.notEqual((await fs.lstat(target)).mtimeMs, 1000);
  context.mock.method(fs, 'open', async (path, flags) => {
    const file = await open(path, flags),
      read = file.read;
    descriptors.push(file);
    context.mock.method(file, 'read', async function (...args) {
      const result = await Reflect.apply(read, this, args);
      if (path === target && !changed) {
        changed = true;
        await fs.utimes(target, 1, 1);
      }
      return result;
    });
    return file;
  });
  syncBuiltinESMExports();
  try {
    await assert.rejects(assertXmlAssets(configuration), /The private XML schema artifact changed/);
    assert.equal(changed, true);
    assert.equal(descriptors.length, 1);
    assert.equal(descriptors[0].fd, -1);
  } finally {
    await Promise.all(descriptors.map((file) => file.close()));
  }
});
