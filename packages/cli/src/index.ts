// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants } from 'node:fs';
import { open, mkdir, lstat, realpath, rename, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import { MODULES, FRAMEWORK_VERSION } from './catalog.js';
import { templates } from './templates.js';
import { dependencyEdit, manifest } from './manifest.js';
import { fields, failure, projectName, releaseVersion } from './validation.js';

export { MODULES, FRAMEWORK_VERSION } from './catalog.js';
export type { OperationOptions } from '@arkenivajs/core';
export interface ProjectOptions extends OperationOptions {
  /** Existing trusted working directory; no ancestor symlink or automatic parent creation. */
  readonly cwd?: string;
  /** Exact published release to reference; no ranges, local paths or install-time scripts. */
  readonly frameworkVersion?: string;
}
export interface ProjectChange {
  readonly directory: string;
  readonly changed: boolean;
  readonly files: readonly string[];
}
type Scope = {
  check(): void;
  mutation(): void;
  readonly cwd: string;
  readonly version: string | undefined;
};

/** Retain the cooperative lock until native work settles, even if the public waiter is canceled. */
async function operation(
  input: ProjectOptions | undefined,
  work: (scope: Scope) => Promise<ProjectChange>,
): Promise<ProjectChange> {
  const options = fields(input === undefined ? {} : input, [
    'cwd',
    'frameworkVersion',
    'signal',
    'timeoutMs',
  ]);
  const cwd = options.cwd === undefined ? process.cwd() : options.cwd;
  if (typeof cwd !== 'string' || !cwd || cwd.length > 4096 || /[\0\r\n]/.test(cwd)) throw failure();
  const timeout = options.timeoutMs ?? 5000;
  if (
    !Number.isSafeInteger(timeout) ||
    typeof timeout !== 'number' ||
    timeout < 1 ||
    timeout > 30000
  )
    throw failure();
  const version =
    options.frameworkVersion === undefined ? undefined : releaseVersion(options.frameworkVersion);
  const controller = new AbortController(),
    signal = AbortSignal.any([
      controller.signal,
      ...(options.signal === undefined ? [] : [captureAbortSignal(options.signal)]),
    ]),
    deadline = performance.now() + timeout;
  let mutated = false;
  const check = () => {
    if (signal.aborted) throw failure('Project operation aborted', 'EK_ABORTED', mutated);
    if (performance.now() >= deadline)
      throw failure('Project operation timed out', 'EK_TIMEOUT', mutated);
  };
  check();
  const task = Promise.resolve().then(async () => {
    check();
    const directory = resolve(cwd);
    if ((await realpath(directory)) !== directory || !(await lstat(directory)).isDirectory())
      throw failure('A real existing working directory is required');
    check();
    return work({
      cwd: directory,
      version,
      check,
      mutation() {
        check();
        mutated = true;
      },
    });
  });
  void task.catch(() => undefined);
  try {
    return await within(() => task, { signal, timeoutMs: timeout });
  } catch (error) {
    if (error instanceof KitError) throw failure(error.message, error.code, mutated);
    throw failure('The project operation could not complete', 'EK_BACKEND_UNAVAILABLE', mutated);
  } finally {
    controller.abort();
  }
}

async function locked<T>(path: string, scope: Scope, work: () => Promise<T>): Promise<T> {
  scope.check();
  let lock: FileHandle;
  try {
    lock = await open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
      0o600,
    );
  } catch {
    throw failure('The project is busy or its lock is unavailable', 'EK_BACKEND_UNAVAILABLE');
  }
  const owned = await lock.stat();
  try {
    scope.check();
    return await work();
  } finally {
    await lock.close();
    const current = await lstat(path).catch(() => undefined);
    if (current?.ino === owned.ino && current.dev === owned.dev) await unlink(path);
  }
}

/** Create an explicit Fastify starter. Existing paths are never overwritten, including empty directories. */
export async function newProject(name: string, options?: ProjectOptions): Promise<ProjectChange> {
  const safeName = projectName(name);
  return operation(options, async (scope) => {
    const directory = join(scope.cwd, safeName);
    return locked(join(scope.cwd, '.' + safeName + '.arkenivajs.lock'), scope, async () => {
      const content = templates(safeName, scope.version ?? FRAMEWORK_VERSION);
      scope.mutation();
      await mkdir(directory, { mode: 0o700 });
      for (const [file, text] of content) {
        scope.check();
        if (file.startsWith('src/')) await mkdir(join(directory, 'src'), { mode: 0o700 });
        const handle = await open(
          join(directory, file),
          constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
          0o600,
        );
        try {
          await handle.writeFile(text);
          await handle.sync();
        } finally {
          await handle.close();
        }
        scope.check();
      }
      return Object.freeze({ directory, changed: true, files: Object.freeze([...content.keys()]) });
    });
  });
}

/** Add one explicitly selected runtime dependency; preserve unrelated manifest bytes and lockfiles. */
export async function addModule(module: string, options?: ProjectOptions): Promise<ProjectChange> {
  if (typeof module !== 'string') throw failure('The selected framework module is unavailable');
  const name =
    typeof module === 'string' && module.startsWith('@arkenivajs/')
      ? module
      : '@arkenivajs/' + module;
  if (!MODULES.includes(name)) throw failure('The selected framework module is unavailable');
  return operation(options, async (scope) =>
    locked(join(scope.cwd, '.arkenivajs.lock'), scope, async () => {
      const path = join(scope.cwd, 'package.json');
      const handle = await open(
        path,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      let original: string, identity: Awaited<ReturnType<FileHandle['stat']>>;
      try {
        identity = await handle.stat();
        if (!identity.isFile() || identity.nlink !== 1 || identity.size > 1048576) throw failure();
        const bytes = Buffer.alloc(1048577);
        let offset = 0;
        while (offset < bytes.length) {
          scope.check();
          const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
          if (!bytesRead) break;
          offset += bytesRead;
        }
        if (offset > 1048576) throw failure();
        original = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, offset));
      } finally {
        await handle.close();
      }
      scope.check();
      const data = manifest(original);
      if (data.type !== 'module') throw failure('The project must use an ESM package manifest');
      const entries = data.dependencies;
      const coreVersion =
        entries && typeof entries === 'object' && !Array.isArray(entries)
          ? Object.getOwnPropertyDescriptor(entries, '@arkenivajs/core')?.value
          : undefined;
      const version = releaseVersion(scope.version ?? coreVersion);
      if (coreVersion !== undefined && coreVersion !== version)
        throw failure('The selected version conflicts with the project core version');
      const next = dependencyEdit(original, name, version);
      if (next === original)
        return Object.freeze({ directory: scope.cwd, changed: false, files: Object.freeze([]) });
      const temporary = join(dirname(path), '.arkenivajs-manifest-' + randomUUID() + '.tmp');
      const candidate = await open(
        temporary,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
        identity.mode & 0o777,
      );
      let committed = false;
      try {
        await candidate.writeFile(next);
        await candidate.sync();
        await candidate.close();
        scope.check();
        const current = await lstat(path);
        if (
          current.ino !== identity.ino ||
          current.dev !== identity.dev ||
          current.size !== identity.size ||
          current.mtimeMs !== identity.mtimeMs ||
          current.nlink !== 1
        )
          throw failure('The manifest changed during the operation');
        scope.mutation();
        await rename(temporary, path);
        committed = true;
        scope.check();
        return Object.freeze({
          directory: scope.cwd,
          changed: true,
          files: Object.freeze(['package.json']),
        });
      } finally {
        await candidate.close().catch(() => undefined);
        if (!committed) await unlink(temporary).catch(() => undefined);
      }
    }),
  );
}
