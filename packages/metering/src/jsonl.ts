import { constants } from 'node:fs';
import { open, realpath, lstat, rename, unlink } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { resolve, relative, dirname, sep, isAbsolute } from 'node:path';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions, MeteringEvent } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import type { MeterExporter } from './index.js';
import { parseMeteringEvent } from './event.js';

/** Dedicated POSIX workspace; parent directories must already exist and remain owner-controlled. */
export interface JsonlExporterOptions {
  readonly workspace: string;
  readonly path: string;
  readonly maxFileBytes?: number;
  readonly retainedFiles?: number;
  readonly rotationIntervalMs?: number;
}
const failure = (message: string, cause?: unknown) =>
  new KitError({ code: 'EK_METER_EXPORT', message, cause });
const absent = (cause: unknown) =>
  !!cause && typeof cause === 'object' && (cause as { code?: unknown }).code === 'ENOENT';
/** Own an exclusive no-follow file/lock and acknowledge only complete fsynced JSON Lines batches. */
export async function createJsonlExporter(options: JsonlExporterOptions): Promise<MeterExporter> {
  const maxBytes = options?.maxFileBytes ?? 10_485_760,
    retained = options?.retainedFiles ?? 5,
    interval = options?.rotationIntervalMs ?? 86_400_000;
  if (
    !options ||
    typeof options.workspace !== 'string' ||
    typeof options.path !== 'string' ||
    !options.path ||
    isAbsolute(options.path) ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes < 65_536 ||
    maxBytes > 1_073_741_824 ||
    !Number.isSafeInteger(retained) ||
    retained < 1 ||
    retained > 100 ||
    !Number.isSafeInteger(interval) ||
    interval < 1 ||
    interval > 2_147_483_647
  )
    throw new KitError({ code: 'EK_CONFIG_INVALID', message: 'Invalid JSONL exporter policy' });
  let lock: FileHandle | undefined, file: FileHandle | undefined, directory: FileHandle | undefined;
  let path = '',
    lockPath = '';
  let existingAge: number;
  const ownedFile = async (name: string, allowMissing = false) => {
    try {
      const info = await lstat(name);
      if (
        !info.isFile() ||
        info.isSymbolicLink() ||
        info.nlink !== 1 ||
        (process.getuid && info.uid !== process.getuid()) ||
        (info.mode & 0o077) !== 0
      )
        throw failure('Meter file is not a private owned regular file');
      return info;
    } catch (cause) {
      if (allowMissing && absent(cause)) return undefined;
      throw cause;
    }
  };
  try {
    const workspace = await realpath(options.workspace);
    path = resolve(workspace, options.path);
    lockPath = path + '.lock';
    const rel = relative(workspace, path);
    if (!rel || rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel))
      throw failure('Meter path is outside the approved workspace');
    const parent = await realpath(dirname(path));
    if (parent !== dirname(path)) throw failure('Meter directory must not contain symbolic links');
    let current = workspace;
    for (const component of ['', ...relative(workspace, parent).split(sep).filter(Boolean)]) {
      if (component) current = resolve(current, component);
      const info = await lstat(current);
      if (
        !info.isDirectory() ||
        info.isSymbolicLink() ||
        (process.getuid && info.uid !== process.getuid()) ||
        (info.mode & 0o022) !== 0
      )
        throw failure('Meter directory must remain owner-controlled');
    }
    directory = await open(
      parent,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    lock = await open(
      lockPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    await lock.sync();
    await ownedFile(path, true);
    for (let index = 1; index <= retained; index++) await ownedFile(path + '.' + index, true);
    file = await open(
      path,
      constants.O_CREAT | constants.O_APPEND | constants.O_RDWR | constants.O_NOFOLLOW,
      0o600,
    );
    await ownedFile(path);
    const existing = await file.stat();
    existingAge = Math.max(0, Date.now() - existing.mtimeMs);
    if (existing.size > 0) {
      const last = Buffer.alloc(1);
      await file.read(last, 0, 1, existing.size - 1);
      if (last[0] !== 10) throw failure('Existing meter file ends with an incomplete record');
    }
    await directory.sync();
  } catch (cause) {
    const cleanup = await Promise.allSettled([file?.close(), directory?.close(), lock?.close()]);
    const errors: unknown[] = cleanup.flatMap((result) =>
      result.status === 'rejected' ? [result.reason] : [],
    );
    if (lock) {
      try {
        await unlink(lockPath);
      } catch (error) {
        errors.push(error);
      }
    }
    if (cause instanceof KitError && errors.length === 0) throw cause;
    throw failure(
      'Unable to own the metering file and lock',
      errors.length ? new AggregateError([cause, ...errors]) : cause,
    );
  }
  let closed = false,
    poisoned = false;
  let rotated = performance.now() - existingAge;
  let writing: Promise<void> | undefined, closing: Promise<void> | undefined;
  const rotate = async () => {
    await file!.sync();
    await file!.close();
    file = undefined;
    await ownedFile(path + '.' + retained, true).then((info) =>
      info ? unlink(path + '.' + retained) : undefined,
    );
    for (let index = retained - 1; index >= 1; index--)
      if (await ownedFile(path + '.' + index, true))
        await rename(path + '.' + index, path + '.' + (index + 1));
    await ownedFile(path);
    await rename(path, path + '.1');
    file = await open(
      path,
      constants.O_CREAT |
        constants.O_EXCL |
        constants.O_APPEND |
        constants.O_WRONLY |
        constants.O_NOFOLLOW,
      0o600,
    );
    await directory!.sync();
    rotated = performance.now();
  };
  return Object.freeze({
    kind: 'jsonl' as const,
    export(events: readonly MeteringEvent[], operation: OperationOptions = {}) {
      if (closed || poisoned)
        return Promise.reject(failure('JSONL exporter is closed or requires recovery'));
      if (writing)
        return Promise.reject(
          new KitError({
            code: 'EK_METER_EXPORT',
            message: 'JSONL writer is busy',
            retryable: true,
          }),
        );
      if (!Array.isArray(events) || events.length < 1 || events.length > 1000)
        return Promise.reject(failure('Invalid JSONL batch size'));
      let lines: readonly string[];
      try {
        lines = events.map((event) => JSON.stringify(parseMeteringEvent(event)) + '\n');
      } catch (cause) {
        return Promise.reject(cause);
      }
      const attemptController = new AbortController();
      const bounded = {
        timeoutMs: operation.timeoutMs ?? 5000,
        signal: AbortSignal.any([
          attemptController.signal,
          ...(operation.signal ? [operation.signal] : []),
        ]),
      };
      const work = (async () => {
        for (const line of lines) {
          await within(() => undefined, bounded);
          const info = await file!.stat();
          if (!info.isFile() || info.nlink !== 1) throw failure('Meter file ownership changed');
          const bytes = Buffer.byteLength(line);
          if (
            info.size > 0 &&
            (info.size + bytes > maxBytes || performance.now() - rotated >= interval)
          )
            await rotate();
          const before = (await file!.stat()).size;
          try {
            await file!.writeFile(line, 'utf8');
          } catch (cause) {
            try {
              await file!.truncate(before);
            } catch {
              poisoned = true;
            }
            throw cause;
          }
        }
        await file!.sync();
        await within(() => undefined, bounded);
      })().catch((cause) => {
        poisoned = true;
        if (cause instanceof KitError) throw cause;
        throw failure('Metering file write or synchronization failed', cause);
      });
      writing = work;
      void work
        .finally(() => {
          writing = undefined;
        })
        .catch(() => undefined);
      return within(() => work, bounded).finally(() => attemptController.abort());
    },
    close(operation: OperationOptions = {}) {
      if (closing) return closing;
      closed = true;
      const cleanup = (async () => {
        try {
          await writing;
        } catch {
          /* Cleanup still releases ownership after a failed write. */
        }
        const errors: unknown[] = [];
        try {
          await file?.close();
        } catch (cause) {
          errors.push(cause);
        }
        let held: Awaited<ReturnType<FileHandle['stat']>> | undefined;
        try {
          held = await lock!.stat();
        } catch (cause) {
          errors.push(cause);
        }
        try {
          await lock!.close();
        } catch (cause) {
          errors.push(cause);
        }
        try {
          const present = await lstat(lockPath);
          if (!held || held.ino !== present.ino || held.dev !== present.dev)
            throw failure('Meter lock ownership changed');
          await unlink(lockPath);
          await directory!.sync();
        } catch (cause) {
          errors.push(cause);
        }
        try {
          await directory!.close();
        } catch (cause) {
          errors.push(cause);
        }
        if (errors.length)
          throw failure('Metering file cleanup failed', new AggregateError(errors));
      })();
      void cleanup.catch(() => undefined);
      closing = within(() => cleanup, operation).catch((cause) => {
        if (cause instanceof KitError) throw cause;
        throw failure('Metering file cleanup failed', cause);
      });
      return closing;
    },
  });
}
