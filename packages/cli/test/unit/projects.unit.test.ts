// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtemp,
  readFile,
  writeFile,
  mkdir,
  rm,
  symlink,
  link,
  stat,
  readdir,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { watch } from 'node:fs';
import { setImmediate } from 'node:timers/promises';
import { promisify } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { newProject, addModule, MODULES, FRAMEWORK_VERSION } from '../../dist/index.js';
import { runCli } from '../../dist/command.js';
import { manifest, dependencyEdit } from '../../dist/manifest.js';

async function fixture(work: (root: string) => Promise<void>) {
  const root = await mkdtemp(join(tmpdir(), 'arkeniva-cli-test-'));
  try {
    await work(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}
const denied = (error: unknown) => error instanceof KitError;

test('The release constant matches package metadata and explicit addition works in an existing ESM project', async () =>
  fixture(async (cwd) => {
    const metadata = JSON.parse(
      await readFile(new URL('../../package.json', import.meta.url), 'utf8'),
    );
    assert.equal(FRAMEWORK_VERSION, metadata.version);
    assert.deepEqual(metadata.bin, { arkenivajs: './dist/bin.js' });
    await writeFile(join(cwd, 'package.json'), '{"name":"existing","type":"module"}\n');
    await assert.rejects(addModule('dns', { cwd }), denied);
    assert.equal((await addModule('dns', { cwd, frameworkVersion: '0.1.0' })).changed, true);
  }));

test('Independent executable processes do not overwrite a competing new project', async () =>
  fixture(async (cwd) => {
    const execute = promisify(execFile),
      bin = new URL('../../dist/bin.js', import.meta.url).pathname;
    const outcomes = await Promise.allSettled([
      execute(process.execPath, [bin, 'new', 'multi-process'], { cwd }),
      execute(process.execPath, [bin, 'new', 'multi-process'], { cwd }),
    ]);
    assert.equal(outcomes.filter((value) => value.status === 'fulfilled').length, 1);
    const data = JSON.parse(await readFile(join(cwd, 'multi-process/package.json'), 'utf8'));
    assert.equal(data.name, 'multi-process');
    assert.deepEqual(await readdir(cwd), ['multi-process']);
  }));

test('A real deadline expires before delayed native work can publish a project', async () =>
  fixture(async (cwd) => {
    const pending = newProject('expired-service', { cwd, timeoutMs: 1 });
    queueMicrotask(() => {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    });
    await assert.rejects(
      pending,
      (error) => error instanceof KitError && error.code === 'EK_TIMEOUT',
    );
    await setImmediate();
    assert.deepEqual(await readdir(cwd), []);
  }));

test('Cancellation during exclusive project writes reports uncertainty and releases only its own lock', async () =>
  fixture(async (cwd) => {
    const controller = new AbortController();
    const watcher = watch(cwd, (_event, name) => {
      if (name === 'partial-service') controller.abort();
    });
    try {
      await assert.rejects(
        newProject('partial-service', { cwd, signal: controller.signal }),
        (error) =>
          error instanceof KitError &&
          error.code === 'EK_ABORTED' &&
          error.details.outcome === 'unknown',
      );
      const deadline = performance.now() + 2000;
      while ((await readdir(cwd)).some((name) => name.endsWith('.lock'))) {
        assert.ok(
          performance.now() < deadline,
          'Private filesystem work must finish and release its lock',
        );
        await setImmediate();
      }
      await assert.rejects(newProject('partial-service', { cwd }), denied);
      assert.deepEqual(await readdir(cwd), ['partial-service']);
    } finally {
      watcher.close();
    }
  }));

test('New projects contain exact minimal dependencies, executable ESM source and the complete license', async () =>
  fixture(async (cwd) => {
    const result = await newProject('hello-service', { cwd });
    assert.equal(result.changed, true);
    assert.equal(Object.isFrozen(result.files), true);
    assert.deepEqual(
      [...result.files].sort(),
      ['.gitignore', 'LICENSE', 'README.md', 'package.json', 'src/main.ts', 'tsconfig.json'].sort(),
    );
    const project = JSON.parse(await readFile(join(result.directory, 'package.json'), 'utf8'));
    assert.deepEqual(project.dependencies, {
      '@arkenivajs/api': FRAMEWORK_VERSION,
      '@arkenivajs/core': FRAMEWORK_VERSION,
      '@arkenivajs/logging': FRAMEWORK_VERSION,
    });
    assert.equal(project.private, true);
    assert.equal(project.type, 'module');
    assert.equal(project.scripts.start, 'node dist/main.js');
    const source = await readFile(join(result.directory, 'src/main.ts'), 'utf8');
    assert.match(source, /plugins: \[loggingPlugin\(\), apiPlugin\(\)\]/);
    assert.match(source, /host: '127.0.0.1'/);
    assert.match(source, /SPDX-License-Identifier: AGPL-3.0-or-later/);
    assert.match(await readFile(join(result.directory, '.gitignore'), 'utf8'), /\*\.patch/);
    const license = await readFile(join(result.directory, 'LICENSE'), 'utf8');
    assert.match(license, /GNU AFFERO GENERAL PUBLIC LICENSE/);
    assert.ok(license.length > 30000);
    assert.equal((await stat(result.directory)).mode & 0o777, 0o700);
    assert.deepEqual(await readdir(cwd), ['hello-service']);
  }));

test('Existing directories, files and symlink destinations are preserved without overwrites', async () =>
  fixture(async (cwd) => {
    await mkdir(join(cwd, 'existing'));
    await writeFile(join(cwd, 'file'), 'preserve');
    await symlink(join(cwd, 'existing'), join(cwd, 'linked'));
    for (const name of ['existing', 'file', 'linked'])
      await assert.rejects(newProject(name, { cwd }), denied);
    assert.equal(await readFile(join(cwd, 'file'), 'utf8'), 'preserve');
    assert.deepEqual(await readdir(join(cwd, 'existing')), []);
  }));

test('Module addition preserves unrelated bytes and repeating it preserves inode, timestamps and lockfile', async () =>
  fixture(async (cwd) => {
    const initial =
      '{\r\n\t"name": "owned-service",\r\n\t"type": "module",\r\n\t"scripts": { "custom": "echo keep" },\r\n\t"dependencies": { "@arkenivajs/core": "0.1.0" }\r\n}\r\n';
    await writeFile(join(cwd, 'package.json'), initial);
    await writeFile(join(cwd, 'pnpm-lock.yaml'), 'unchanged');
    const result = await addModule('data-csv', { cwd });
    assert.deepEqual(result.files, ['package.json']);
    const text = await readFile(join(cwd, 'package.json'), 'utf8');
    assert.ok(text.includes('\t"scripts": { "custom": "echo keep" }'));
    assert.ok(text.includes('\r\n'));
    assert.equal(JSON.parse(text).dependencies['@arkenivajs/data-csv'], '0.1.0');
    const before = await stat(join(cwd, 'package.json'));
    assert.equal((await addModule('@arkenivajs/data-csv', { cwd })).changed, false);
    const after = await stat(join(cwd, 'package.json'));
    assert.equal(before.ino, after.ino);
    assert.equal(before.mtimeMs, after.mtimeMs);
    assert.equal(await readFile(join(cwd, 'pnpm-lock.yaml'), 'utf8'), 'unchanged');
    assert.deepEqual((await readdir(cwd)).sort(), ['package.json', 'pnpm-lock.yaml']);
  }));

test('Only existing module names and exact compatible framework versions are admitted', async () =>
  fixture(async (cwd) => {
    await newProject('demo', { cwd, frameworkVersion: '1.2.3-rc.1' });
    const project = join(cwd, 'demo');
    assert.equal((await addModule('dns', { cwd: project })).changed, true);
    for (const name of [
      'no-module',
      '../api',
      'unimplemented-module',
      'https://untrusted.invalid',
      '__proto__',
    ])
      await assert.rejects(addModule(name, { cwd: project }), denied);
    for (const version of ['latest', '^1.2.3', 'file:/tmp/a', '', '1.2', '1.2.3\n'])
      await assert.rejects(addModule('http', { cwd: project, frameworkVersion: version }), denied);
    await assert.rejects(addModule('http', { cwd: project, frameworkVersion: '2.0.0' }), denied);
    assert.equal(MODULES.includes('@arkenivajs/database-oracle'), true);
    assert.equal(MODULES.includes('@arkenivajs/cli'), false);
  }));

test('Names cannot traverse directories, inject source or use unsafe filesystem segments', async () =>
  fixture(async (cwd) => {
    for (const name of [
      '../escape',
      '/absolute',
      '.',
      '..',
      'a/b',
      'a\\b',
      'a\0b',
      'a\nb',
      "a';x",
      'A',
      'con',
      '',
      'x'.repeat(64),
    ])
      await assert.rejects(newProject(name, { cwd }), denied);
    assert.deepEqual(await readdir(cwd), []);
  }));

test('Strict manifest parsing rejects duplicates, comments, prototype keys, excessive depth and invalid dependency sections', () => {
  for (const text of [
    '[]',
    '{} garbage',
    '{"a":1,"a":2}',
    '{"a":{"x":0,"x":1}}',
    '{/*x*/"a":0}',
    '{"__proto__":{}}',
    '{"constructor":0}',
    '{"x":' + '['.repeat(40) + '0' + ']'.repeat(40) + '}',
    '{"x":"' + 'a'.repeat(1048576) + '"}',
  ])
    assert.throws(() => manifest(text), denied);
  for (const value of [null, [], 'wrong'])
    assert.throws(
      () => dependencyEdit(JSON.stringify({ dependencies: value }), '@arkenivajs/dns', '0.1.0'),
      denied,
    );
  for (const section of [
    'dependencies',
    'devDependencies',
    'optionalDependencies',
    'peerDependencies',
  ])
    assert.throws(
      () =>
        dependencyEdit(
          JSON.stringify({ [section]: { '@arkenivajs/dns': '9.0.0' } }),
          '@arkenivajs/dns',
          '0.1.0',
        ),
      denied,
    );
  assert.equal(Object.getPrototypeOf(manifest('{}')), null);
});

test('Malformed, oversized, non-UTF8, symlink and hardlinked manifests cannot alter external files', async () =>
  fixture(async (cwd) => {
    const path = join(cwd, 'package.json'),
      outside = join(cwd, 'outside.json');
    const original = '{"type":"module","dependencies":{"@arkenivajs/core":"0.1.0"}}';
    await writeFile(outside, original);
    for (const content of [
      '{broken',
      '{}',
      '{"type":"commonjs"}',
      ' '.repeat(1048577),
      Buffer.from([0xff, 0xfe]),
    ]) {
      await writeFile(path, content);
      await assert.rejects(addModule('dns', { cwd }), denied);
    }
    await rm(path);
    await symlink(outside, path);
    await assert.rejects(addModule('dns', { cwd }), denied);
    await rm(path);
    await link(outside, path);
    await assert.rejects(addModule('dns', { cwd }), denied);
    assert.equal(await readFile(outside, 'utf8'), original);
    await rm(path);
    await mkdir(path);
    await assert.rejects(addModule('dns', { cwd }), denied);
    assert.deepEqual((await readdir(cwd)).sort(), ['outside.json', 'package.json']);
  }));

test('Cooperating concurrent creators and manifest edits have one writer and never lose updates silently', async () =>
  fixture(async (cwd) => {
    const creates = await Promise.allSettled([
      newProject('shared', { cwd }),
      newProject('shared', { cwd }),
    ]);
    assert.equal(creates.filter((entry) => entry.status === 'fulfilled').length, 1);
    const project = join(cwd, 'shared');
    const updates = await Promise.allSettled([
      addModule('dns', { cwd: project }),
      addModule('http', { cwd: project }),
    ]);
    assert.equal(updates.filter((entry) => entry.status === 'fulfilled').length, 1);
    for (const name of ['dns', 'http']) await addModule(name, { cwd: project });
    const data = JSON.parse(await readFile(join(project, 'package.json'), 'utf8'));
    assert.equal(data.dependencies['@arkenivajs/dns'], '0.1.0');
    assert.equal(data.dependencies['@arkenivajs/http'], '0.1.0');
    assert.equal(
      (await readdir(project)).some((name) => name.includes('arkenivajs')),
      false,
    );
  }));

test('Pre-cancellation, invalid timeouts and accessors fail before any filesystem mutation', async () =>
  fixture(async (cwd) => {
    await assert.rejects(
      newProject('aborted', { cwd, signal: AbortSignal.abort() }),
      (error) => error instanceof KitError && error.code === 'EK_ABORTED',
    );
    for (const timeoutMs of [0, -1, 1.1, NaN, Infinity, 30001])
      await assert.rejects(newProject('invalid', { cwd, timeoutMs }), denied);
    let reads = 0;
    await assert.rejects(
      newProject(
        'invalid',
        Object.defineProperty({ cwd }, 'timeoutMs', {
          get() {
            reads++;
            return 1;
          },
        }),
      ),
      denied,
    );
    assert.equal(reads, 0);
    await assert.rejects(
      newProject('invalid', { cwd, signal: { aborted: false } as AbortSignal }),
      denied,
    );
    await assert.rejects(newProject('invalid', { cwd, unknown: true } as never), denied);
    assert.deepEqual(await readdir(cwd), []);
  }));

test('Existing foreign locks and symlinked working directories are not removed or followed', async () =>
  fixture(async (cwd) => {
    const marker = join(cwd, '.locked.arkenivajs.lock');
    await writeFile(marker, 'owned elsewhere');
    await assert.rejects(newProject('locked', { cwd }), denied);
    assert.equal(await readFile(marker, 'utf8'), 'owned elsewhere');
    await mkdir(join(cwd, 'real'));
    await symlink(join(cwd, 'real'), join(cwd, 'alias'));
    await assert.rejects(newProject('child', { cwd: join(cwd, 'alias') }), denied);
    assert.deepEqual(await readdir(join(cwd, 'real')), []);
  }));

test('Native argument parsing rejects unsupported flags and keeps hostile arguments out of diagnostics', async () =>
  fixture(async (cwd) => {
    let stdout = '',
      stderr = '';
    const output = {
      stdout: (text: string) => {
        stdout += text;
      },
      stderr: (text: string) => {
        stderr += text;
      },
    };
    assert.equal(await runCli(['--help'], output), 0);
    assert.match(stdout, /Usage:/);
    assert.equal(await runCli(['--version'], output), 0);
    for (const args of [
      [],
      ['new'],
      ['new', 'ok', 'extra'],
      ['add', 'dns', '--unknown'],
      ['--help', 'new', 'ok'],
      ['new', '../private-value'],
    ])
      assert.equal(await runCli(args, output, { cwd }), 1);
    assert.equal(stderr.includes('private-value'), false);
    assert.equal(await runCli(['new', 'command-service'], output, { cwd }), 0);
    assert.equal(await runCli(['add', 'dns'], output, { cwd: join(cwd, 'command-service') }), 0);
    assert.equal(await runCli(['add', 'dns'], output, { cwd: join(cwd, 'command-service') }), 0);
    assert.match(stdout, /already present/);
  }));

test('The actual Node executable entry point prints safe help and edits an owned project', async () =>
  fixture(async (cwd) => {
    const execute = promisify(execFile),
      bin = new URL('../../dist/bin.js', import.meta.url);
    const { stdout } = await execute(process.execPath, [bin.pathname, '--help'], { cwd });
    assert.match(stdout, /Usage:/);
    await execute(process.execPath, [bin.pathname, 'new', 'bin-service'], { cwd });
    await execute(process.execPath, [bin.pathname, 'add', 'dns'], {
      cwd: join(cwd, 'bin-service'),
    });
    assert.equal(
      JSON.parse(await readFile(join(cwd, 'bin-service/package.json'), 'utf8')).dependencies[
        '@arkenivajs/dns'
      ],
      FRAMEWORK_VERSION,
    );
  }));
