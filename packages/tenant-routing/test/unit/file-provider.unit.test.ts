// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, mkdir, symlink, link, rm, truncate } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { spawnSync } from 'node:child_process';
import { KitError, type OperationOptions } from '@arkenivajs/core';
import { tenantRegistryFileProvider, type TenantRegistryFileOptions } from '../../dist/index.js';
import { registryContentChecksum } from '../../dist/registry.js';

function registry(generation = 1, revision = 'blue', changed = false) {
  const value = {
    schemaVersion: '1.1.0' as const,
    revision,
    activationGeneration: generation,
    contentChecksum: '',
    activatedAt: '2026-01-01T00:00:00.000Z',
    operations: [],
    bindings: [],
    implementations: changed
      ? [{ id: 'installed', kind: 'handler' as const, handlerKey: 'local' }]
      : [],
  };
  value.contentChecksum = registryContentChecksum(value);
  return value;
}
function safe(error: unknown) {
  assert.ok(error instanceof KitError);
  assert.equal(error.code, 'EK_TROUTE_REGISTRY');
  assert.equal(error.message, 'Invalid tenant routing registry');
  assert.equal(error.cause, undefined);
  return true;
}
async function fixture(
  run: (options: TenantRegistryFileOptions, directory: string) => Promise<void>,
) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-tenant-registry-'));
  const path = join(directory, 'registry.json');
  try {
    await chmod(directory, 0o700);
    await writeFile(path, JSON.stringify(registry()), { mode: 0o600 });
    await run({ absolutePath: path, maxBytes: 1048576, environment: 'test' }, directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('File provider validates configuration without opening a file or invoking accessors', () => {
  let effects = 0;
  const valid = { absolutePath: '/run/private/registry.json', maxBytes: 1024 };
  const getter = Object.defineProperty({}, 'absolutePath', {
    enumerable: true,
    get() {
      effects++;
      return valid.absolutePath;
    },
  });
  const proxy = new Proxy(valid, {
    getPrototypeOf() {
      effects++;
      return Object.prototype;
    },
  });
  const roots = new Proxy([], {
    get() {
      effects++;
      return undefined;
    },
  });
  for (const input of [
    null,
    [],
    getter,
    proxy,
    { ...valid, unknown: true },
    ...[
      'relative.json',
      '/run/private/../registry.json',
      '/run//registry.json',
      '/run/file\0.json',
    ].map((absolutePath) => ({ ...valid, absolutePath })),
    ...[0, -1, 1.5, Infinity, 134217729].map((maxBytes) => ({ ...valid, maxBytes })),
    { ...valid, environment: 'staging' },
    { ...valid, publicRoots: roots },
    { ...valid, publicRoots: new Array(1) },
    { ...valid, publicRoots: ['relative'] },
    { ...valid, activationCheckpoint: {} },
    {
      ...valid,
      activationCheckpoint: Object.defineProperty({}, 'accept', {
        get() {
          effects++;
          return () => {};
        },
      }),
    },
  ])
    assert.throws(() => tenantRegistryFileProvider(input as TenantRegistryFileOptions), safe);
  assert.equal(effects, 0);
  assert.ok(Object.isFrozen(tenantRegistryFileProvider(valid)));
});

test('File provider loads a deeply frozen independent snapshot and captures its policy', async () =>
  fixture(async (options) => {
    const mutable = { ...options, publicRoots: [] as string[] };
    const provider = tenantRegistryFileProvider(mutable);
    mutable.absolutePath = '/missing';
    mutable.maxBytes = 1;
    mutable.publicRoots.push('/');
    const original = await provider.loadSnapshot();
    assert.ok(Object.isFrozen(original));
    assert.ok(Object.isFrozen(original.implementations));
    await writeFile(options.absolutePath, JSON.stringify(registry(2, 'green', true)));
    assert.equal(original.revision, 'blue');
    assert.equal(original.implementations.length, 0);
    assert.equal((await provider.loadSnapshot()).revision, 'green');
  }));

test('Private deployment files are mandatory and production is the default', async () =>
  fixture(async (options) => {
    const { environment: _environment, ...production } = options;
    void _environment;
    await assert.rejects(tenantRegistryFileProvider(production).loadSnapshot(), safe);
    for (const mode of [0o644, 0o620, 0o700, 0o4600]) {
      await chmod(options.absolutePath, mode);
      await assert.rejects(tenantRegistryFileProvider(options).loadSnapshot(), safe);
    }
    await chmod(options.absolutePath, 0o640);
    assert.equal((await tenantRegistryFileProvider(options).loadSnapshot()).revision, 'blue');
  }));

test('File provider refuses public roots and their filesystem aliases', async () =>
  fixture(async (options, directory) => {
    assert.throws(() => tenantRegistryFileProvider({ ...options, publicRoots: [directory] }), safe);
    assert.throws(() => tenantRegistryFileProvider({ ...options, publicRoots: ['/'] }), safe);
    const alias = join(directory, 'static-alias');
    await symlink(directory, alias);
    await assert.rejects(
      tenantRegistryFileProvider({ ...options, publicRoots: [alias] }).loadSnapshot(),
      safe,
    );
    const unrelated = join(directory, 'static');
    await mkdir(unrelated, { mode: 0o700 });
    assert.equal(
      (await tenantRegistryFileProvider({ ...options, publicRoots: [unrelated] }).loadSnapshot())
        .revision,
      'blue',
    );
  }));

test('Symlinks, hard links, directories and FIFO inputs fail before registry publication', async () =>
  fixture(async (options, directory) => {
    const linked = join(directory, 'linked.json');
    await symlink(options.absolutePath, linked);
    await assert.rejects(
      tenantRegistryFileProvider({ ...options, absolutePath: linked }).loadSnapshot(),
      safe,
    );
    const alias = join(directory, 'alias');
    await symlink(directory, alias);
    await assert.rejects(
      tenantRegistryFileProvider({
        ...options,
        absolutePath: join(alias, 'registry.json'),
      }).loadSnapshot(),
      safe,
    );
    await assert.rejects(
      tenantRegistryFileProvider({ ...options, absolutePath: directory }).loadSnapshot(),
      safe,
    );
    const hard = join(directory, 'hard.json');
    await link(options.absolutePath, hard);
    await assert.rejects(tenantRegistryFileProvider(options).loadSnapshot(), safe);
    await rm(hard);
    const pipe = join(directory, 'pipe');
    assert.equal(spawnSync('mkfifo', [pipe]).status, 0);
    await assert.rejects(
      tenantRegistryFileProvider({ ...options, absolutePath: pipe }).loadSnapshot({
        timeoutMs: 1000,
      }),
      safe,
    );
  }));

test('Bounded file reads reject malformed UTF-8, duplicate keys, empty and sparse oversized files', async () =>
  fixture(async (options) => {
    for (const content of [
      Buffer.from([0xc0, 0xaf]),
      Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('{}')]),
      Buffer.alloc(0),
      Buffer.from('{"x":1,"x":2}'),
      Buffer.from('{'),
    ]) {
      await writeFile(options.absolutePath, content);
      await assert.rejects(tenantRegistryFileProvider(options).loadSnapshot(), safe);
    }
    await truncate(options.absolutePath, 134217729);
    await assert.rejects(tenantRegistryFileProvider(options).loadSnapshot(), safe);
  }));

test('File activation rejects changed content under one revision and supports rollback under a newer generation', async () =>
  fixture(async (options) => {
    const provider = tenantRegistryFileProvider(options);
    await provider.loadSnapshot();
    await provider.loadSnapshot();
    for (const candidate of [registry(2, 'blue', true), registry(1, 'green', true)]) {
      await writeFile(options.absolutePath, JSON.stringify(candidate));
      await assert.rejects(provider.loadSnapshot(), safe);
    }
    await writeFile(options.absolutePath, JSON.stringify(registry(2, 'green', true)));
    assert.equal((await provider.loadSnapshot()).activationGeneration, 2);
    await writeFile(options.absolutePath, JSON.stringify(registry()));
    await assert.rejects(provider.loadSnapshot(), safe);
    await writeFile(options.absolutePath, JSON.stringify(registry(3, 'blue')));
    assert.equal((await provider.loadSnapshot()).revision, 'blue');
  }));

test('Checkpoint methods are captured with their receiver and failures cannot publish a snapshot', async () =>
  fixture(async (options) => {
    const calls: { scope: string; activationGeneration: number }[] = [];
    class Checkpoint {
      fail = true;
      async accept(
        input: { scope: string; activationGeneration: number },
        operation?: OperationOptions,
      ) {
        calls.push(input);
        assert.ok(operation?.signal);
        assert.equal(operation?.timeoutMs, 1000);
        if (this.fail) throw new Error('Private checkpoint failure');
      }
    }
    const checkpoint = new Checkpoint(),
      provider = tenantRegistryFileProvider({ ...options, activationCheckpoint: checkpoint });
    await assert.rejects(provider.loadSnapshot({ timeoutMs: 1000 }), safe);
    checkpoint.fail = false;
    checkpoint.accept = async () => {
      throw new Error('Replacement must not execute');
    };
    assert.equal((await provider.loadSnapshot({ timeoutMs: 1000 })).revision, 'blue');
    assert.equal(calls.length, 2);
    assert.equal(calls[0]!.scope, calls[1]!.scope);
    assert.match(calls[0]!.scope, /^file:[0-9a-f]{64}$/);
  }));

test('Invalid operation options and pre-aborted signals fail before checkpoint I/O', async () =>
  fixture(async (options) => {
    let effects = 0;
    const provider = tenantRegistryFileProvider({
      ...options,
      activationCheckpoint: {
        accept: async () => {
          effects++;
        },
      },
    });
    const aborted = new AbortController();
    aborted.abort();
    const getter = Object.defineProperty({}, 'timeoutMs', {
      enumerable: true,
      get() {
        effects++;
        return 1000;
      },
    });
    for (const operation of [
      { timeoutMs: 0 },
      { timeoutMs: -1 },
      { timeoutMs: 1.5 },
      { signal: aborted.signal },
      { signal: {} },
      getter,
    ])
      await assert.rejects(provider.loadSnapshot(operation as OperationOptions), safe);
    assert.equal(effects, 0);
    assert.equal((await provider.loadSnapshot()).revision, 'blue');
    assert.equal(effects, 1);
  }));

test('Timed-out checkpoint work retains single-load ownership and cannot publish a late activation', async () =>
  fixture(async (options) => {
    let enter!: () => void, release!: () => void;
    const entered = new Promise<void>((resolve) => {
        enter = resolve;
      }),
      blocked = new Promise<void>((resolve) => {
        release = resolve;
      });
    let first = true,
      signal: AbortSignal | undefined;
    const provider = tenantRegistryFileProvider({
      ...options,
      activationCheckpoint: {
        async accept(_input, operation) {
          if (first) {
            first = false;
            signal = operation?.signal;
            enter();
            await blocked;
          }
        },
      },
    });
    await writeFile(options.absolutePath, JSON.stringify(registry(10, 'late')));
    const result = provider.loadSnapshot({ timeoutMs: 200 });
    const rejection = assert.rejects(result, safe);
    await entered;
    await rejection;
    assert.ok(signal?.aborted);
    await assert.rejects(provider.loadSnapshot(), safe);
    release();
    await nextTurn();
    await nextTurn();
    await writeFile(options.absolutePath, JSON.stringify(registry()));
    assert.equal((await provider.loadSnapshot()).activationGeneration, 1);
  }));
