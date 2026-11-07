// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createApplication, KitError } from '@arkenivajs/core';
import { dataXmlPlugin } from '../../dist/index.js';

test('Public XML startup rejects a different regular schema inode before reading it', async (context) => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'arkenivajs-xsd-identity-')),
    schema = join(directory, 'invoice.xsd'),
    replacement = join(directory, 'replacement.xsd'),
    prefix = '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">',
    originalSource = prefix + '<xs:element name="original" type="xs:string"/></xs:schema>',
    replacementSource = prefix + '<xs:element name="replaced" type="xs:string"/></xs:schema>';
  assert.equal(Buffer.byteLength(originalSource), Buffer.byteLength(replacementSource));
  await fs.writeFile(schema, originalSource, { mode: 0o600 });
  await fs.writeFile(replacement, replacementSource, { mode: 0o600 });
  const before = await fs.lstat(schema),
    other = await fs.lstat(replacement),
    open = fs.open,
    lstat = fs.lstat,
    spawn = childProcess.spawn,
    executable = await fs.lstat('/usr/bin/prlimit');
  assert.notEqual(before.ino, other.ino);
  let replaced = false,
    reads = 0,
    probes = 0,
    compilerCalls = 0,
    descriptor: FileHandle | undefined;

  // Model only the optional backend probes; schema metadata, replacement and reads stay real.
  context.mock.method(fs, 'lstat', ((path: string, options: unknown) =>
    path === '/usr/bin/xmllint'
      ? Promise.resolve(executable)
      : Reflect.apply(lstat, fs, [path, options])) as typeof fs.lstat);
  context.mock.method(childProcess, 'spawn', ((
    program: string,
    args: readonly string[],
    options: childProcess.SpawnOptions,
  ) => {
    if (program === '/usr/bin/prlimit') {
      compilerCalls++;
      throw new Error('A replaced schema must not reach the native compiler');
    }
    assert.ok(
      (program === '/usr/bin/dpkg-query' && args[0] === '-W') ||
        (program === '/usr/bin/xmllint' && args[0] === '--version'),
    );
    probes++;
    const output =
      program === '/usr/bin/dpkg-query'
        ? 'libxml2\t2.9.14+dfsg-1.3ubuntu3.10\nlibxml2-utils\t2.9.14+dfsg-1.3ubuntu3.10\n'
        : 'libxml version 20914 Schemas\n';
    return spawn(process.execPath, ['-e', 'process.stdout.write(' + JSON.stringify(output) + ')'], {
      ...options,
      env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' },
    });
  }) as typeof childProcess.spawn);
  context.mock.method(fs, 'open', async (path: string, flags: number) => {
    if (path !== schema) return open(path, flags);
    assert.equal(replaced, false);
    replaced = true;
    await fs.rename(replacement, schema);
    descriptor = await open(path, flags);
    const opened = await descriptor.stat();
    assert.equal(opened.dev, other.dev);
    assert.equal(opened.ino, other.ino);
    const read = descriptor.read;
    context.mock.method(descriptor, 'read', function (this: FileHandle, ...args: unknown[]) {
      reads++;
      return Reflect.apply(read, this, args) as ReturnType<FileHandle['read']>;
    });
    return descriptor;
  });
  syncBuiltinESMExports();
  const app = await createApplication({
    service: { name: 'xml-schema-identity', version: '1.0.0', environment: 'test' },
    plugins: [
      dataXmlPlugin({
        defaults: {},
        policy: {
          maxConcurrent: 1,
          timeoutMs: 5000,
          maxInputBytes: 4096,
          maxOutputBytes: 16384,
        },
        xsdSchemaFiles: { invoice: schema },
      }),
    ],
  });
  try {
    await assert.rejects(
      app.start(),
      (error: unknown) =>
        error instanceof KitError &&
        error.code === 'EK_PLUGIN_FAILED' &&
        error.cause instanceof KitError &&
        error.cause.code === 'EK_XML_SECURITY',
    );
    assert.equal(probes, 2);
    assert.equal(replaced, true);
    assert.equal(reads, 0);
    assert.equal(compilerCalls, 0);
    assert.ok(descriptor);
    assert.equal(descriptor.fd, -1);
    assert.equal(await fs.readFile(schema, 'utf8'), replacementSource);
  } finally {
    await app.stop();
    context.diagnostic(
      JSON.stringify({ replaced, reads, compilerCalls, closed: descriptor?.fd === -1 }),
    );
    context.mock.restoreAll();
    syncBuiltinESMExports();
    await descriptor?.close();
    await fs.rm(directory, { recursive: true, force: true });
  }
});
