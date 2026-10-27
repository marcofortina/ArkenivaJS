// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { performance } from 'node:perf_hooks';
import { finished } from 'node:stream/promises';
import { quote } from 'shell-quote';
import type { ClientChannel, FileEntry } from 'ssh2';
import type { OperationOptions } from '@arkenivajs/core';
import { KitError } from '@arkenivajs/core';
import type {
  SftpService,
  SshService,
  SftpOptions,
  SftpRenameOptions,
  SftpEntry,
} from './contracts.js';
import type { Settings } from './settings.js';
import { identifier, remotePath } from './settings.js';
import { fields, failure, integer, method, property, text } from './validation.js';
import { Connection, bytes } from './connection.js';
import { Request, operation } from './request.js';
import type { Observers } from './observation.js';
import { recorder } from './observation.js';

function call(
  input: SftpOptions | SftpRenameOptions | undefined,
  settings: Settings,
  kind: 'transfer' | 'rename',
) {
  const value = fields(input ?? {}, [
    'signal',
    'timeoutMs',
    'overwrite',
    ...(kind === 'transfer' ? ['maxBytes'] : ['requireAtomic']),
  ]);
  if (value.overwrite !== undefined && !['fail', 'replace'].includes(value.overwrite as string))
    throw failure('EK_CONFIG_INVALID');
  if (value.requireAtomic !== undefined && typeof value.requireAtomic !== 'boolean')
    throw failure('EK_CONFIG_INVALID');
  const requested = operation(
    {
      ...(value.signal === undefined ? {} : { signal: value.signal as AbortSignal }),
      ...(value.timeoutMs === undefined ? {} : { timeoutMs: value.timeoutMs as number }),
    },
    settings.timeoutMs,
  );
  return {
    options: {
      timeoutMs: requested.timeoutMs,
      ...(requested.signal ? { signal: requested.signal } : {}),
    },
    overwrite: value.overwrite ?? 'fail',
    requireAtomic: value.requireAtomic === true,
    maximum:
      kind === 'transfer' && value.maxBytes !== undefined
        ? integer(value.maxBytes, Math.max(settings.maxInputBytes, settings.maxOutputBytes))
        : undefined,
  };
}
type Task = { readonly request: Request<unknown>; readonly end: Promise<void> };

/** Profiles serialize native SFTP commands; the global admission bound has no pending queue. */
export function managedService(
  settings: Settings,
  applicationSignal: AbortSignal,
  ready: () => boolean,
  observers: Observers = {},
) {
  const connections = new Map<string, Connection>(),
    active = new Map<string, Task>(),
    observe = recorder(observers);
  let closed = false;
  const check = () => {
    if (closed || applicationSignal.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!ready()) throw failure('EK_LIFECYCLE_STATE');
  };
  const profile = (name: string) => {
    const found = settings.connections.find((item) => item.name === identifier(name));
    if (!found) throw failure();
    return found;
  };
  async function launch<T>(
    name: string,
    options: OperationOptions | undefined,
    kind: 'connect' | 'upload' | 'download' | 'list' | 'rename' | 'exec',
    work: (connection: Connection, request: Request<T>) => Promise<T>,
    initializing = false,
  ): Promise<T> {
    if (!initializing) check();
    if (closed || applicationSignal.aborted) throw failure('EK_RESOURCE_CLOSED');
    const configured = profile(name);
    operation(options, settings.timeoutMs);
    if (active.has(name) || active.size >= settings.maxConcurrent) throw failure();
    let connection = connections.get(name);
    if (!connection?.usable) {
      connection?.destroy();
      if (connection) await connection.closed;
      if (closed || applicationSignal.aborted) throw failure('EK_RESOURCE_CLOSED');
      // Admission has not yet yielded, except while acknowledging a previous physical close.
      if (active.has(name) || active.size >= settings.maxConcurrent) throw failure();
      connection = new Connection(settings, configured);
      connections.set(name, connection);
    }
    const owned = connection,
      started = performance.now();
    let wire = 0;
    const count = (part: Buffer) => {
      wire += part.length;
      if (wire > settings.maxInputBytes + settings.maxOutputBytes + 4 * 1024 * 1024)
        request.stop('EK_SFTP_TRANSFER');
    };
    const request = new Request<T>(
      settings.timeoutMs,
      options,
      applicationSignal,
      () => owned.destroy(),
      async (request) => {
        owned.socket.on('data', count);
        if (!owned.usable) await owned.connect(request);
        request.check();
        return work(owned, request);
      },
    );
    let outcome: 'ok' | 'error' = 'ok';
    void request.result.catch(() => {
      outcome = 'error';
    });
    const end = request.done
      .then(async () => {
        owned.socket.removeListener('data', count);
        if (!owned.usable) {
          owned.destroy();
          await owned.closed;
        }
      })
      .finally(() => {
        active.delete(name);
        observe.complete(kind, outcome, Math.max(0, performance.now() - started));
        observe.measure(
          'connections.active',
          [...connections.values()].filter((item) => item.usable).length,
        );
        observe.measure('operations.active', active.size);
      });
    active.set(name, { request: request as Request<unknown>, end });
    return request.result.then(
      async (value) => {
        await end;
        return value;
      },
      async (error: unknown) => {
        if (!(error instanceof KitError) || !['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code))
          await end;
        throw error;
      },
    );
  }
  const sftp = Object.freeze<SftpService>({
    async upload(name, source, suppliedPath, input) {
      check();
      const path = remotePath(suppliedPath),
        options = call(input, settings, 'transfer'),
        maximum = Math.min(settings.maxInputBytes, options.maximum ?? settings.maxInputBytes),
        iterate = method<() => AsyncIterator<Uint8Array>>(source, Symbol.asyncIterator);
      return launch(name, options.options, 'upload', async (connection, request) => {
        const target = await connection.path(path, true, request);
        if (target && (!target.isFile() || options.overwrite === 'fail')) throw failure();
        const iterator = iterate(),
          next = method<() => Promise<IteratorResult<Uint8Array>>>(iterator, 'next'),
          startedAt = new Date().toISOString(),
          hash = createHash('sha256');
        let transferredBytes = 0,
          ended = false;
        request.submitted = true;
        const stream = connection.native.createWriteStream(path, {
          flags: options.overwrite === 'replace' ? 'w' : 'wx',
          mode: 0o600,
          highWaterMark: 64 * 1024,
        });
        const complete = finished(stream);
        void complete.catch(() => undefined);
        try {
          for (;;) {
            const item = fields(await request.wait(next()), ['value', 'done']);
            if (typeof item.done !== 'boolean' && item.done !== undefined) throw failure();
            if (item.done) {
              ended = true;
              break;
            }
            const part = bytes(item.value, Math.min(1024 * 1024, maximum - transferredBytes));
            try {
              transferredBytes += part.length;
              hash.update(part);
              // The native stream can emit an open error without invoking queued write callbacks.
              await request.wait(
                Promise.race([
                  new Promise<void>((resolve, reject) =>
                    stream.write(part, (error) =>
                      error ? reject(failure('EK_SFTP_TRANSFER', true)) : resolve(),
                    ),
                  ),
                  complete.then(() => {
                    throw failure('EK_SFTP_TRANSFER', true);
                  }),
                ]),
              );
            } finally {
              part.fill(0);
            }
          }
          stream.end();
          await request.wait(complete);
          observe.measure('upload.bytes', transferredBytes);
          return Object.freeze({
            remotePath: path,
            transferredBytes,
            startedAt,
            finishedAt: new Date().toISOString(),
            sha256: hash.digest('hex'),
          });
        } finally {
          if (!stream.closed) stream.destroy();
          await complete.catch(() => undefined);
          if (!ended) {
            if (property(iterator, 'return') !== undefined)
              await method<() => Promise<unknown>>(iterator, 'return')();
          }
        }
      });
    },
    async download(name, suppliedPath, destination, input) {
      check();
      if (typeof destination !== 'function') throw failure();
      const path = remotePath(suppliedPath),
        options = call(input, settings, 'transfer'),
        maximum = Math.min(settings.maxOutputBytes, options.maximum ?? settings.maxOutputBytes);
      return launch(name, options.options, 'download', async (connection, request) => {
        const stat = await connection.path(path, false, request);
        if (!stat?.isFile() || stat.size > maximum) throw failure();
        const stream = connection.native.createReadStream(path, { highWaterMark: 64 * 1024 }),
          complete = finished(stream),
          hash = createHash('sha256'),
          startedAt = new Date().toISOString();
        void complete.catch(() => undefined);
        let transferredBytes = 0;
        try {
          for await (const raw of stream) {
            request.check();
            const part = bytes(raw, Math.min(1024 * 1024, maximum - transferredBytes));
            transferredBytes += part.length;
            hash.update(part);
            request.submitted = true;
            await request.wait(Promise.resolve(destination(new Uint8Array(part))));
          }
          await request.wait(complete);
          observe.measure('download.bytes', transferredBytes);
          return Object.freeze({
            remotePath: path,
            transferredBytes,
            startedAt,
            finishedAt: new Date().toISOString(),
            sha256: hash.digest('hex'),
          });
        } finally {
          stream.destroy();
          await complete.catch(() => undefined);
        }
      });
    },
    async list(name, suppliedPath, options) {
      check();
      const path = remotePath(suppliedPath);
      return launch(name, options, 'list', async (connection, request) => {
        if (!(await connection.path(path, false, request))?.isDirectory()) throw failure();
        const native = connection.native.sftp,
          handle = await request.wait(
            new Promise<Buffer>((resolve, reject) =>
              native.opendir(path, (error, handle) =>
                error ? reject(failure()) : resolve(handle),
              ),
            ),
          );
        const entries: SftpEntry[] = [];
        let size = 0,
          encodedBytes = 0;
        try {
          for (;;) {
            const batch = await request.wait(
              new Promise<FileEntry[] | false>((resolve, reject) =>
                native.readdir(handle, (error, items) => {
                  if (error && 'code' in error && error.code === 1) resolve(false);
                  else if (error) reject(failure());
                  else resolve(items);
                }),
              ),
            );
            if (batch === false) break;
            for (const entry of batch) {
              const name = text(entry.filename, 255);
              if (name === '.' || name === '..') continue;
              if (
                name.includes('/') ||
                name.includes('\\') ||
                [...name].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
              )
                throw failure();
              const full = remotePath((path === '/' ? '' : path) + '/' + name),
                stat = entry.attrs;
              if (++size > 10000 || !Number.isSafeInteger(stat.size) || stat.size < 0)
                throw failure();
              const kind = stat.mode & constants.S_IFMT;
              const type =
                kind === constants.S_IFREG
                  ? 'file'
                  : kind === constants.S_IFDIR
                    ? 'directory'
                    : kind === constants.S_IFLNK
                      ? 'link'
                      : undefined;
              if (!type) throw failure();
              entries.push(Object.freeze({ path: full, sizeBytes: stat.size, type }));
              encodedBytes += Buffer.byteLength(full) + 32;
              if (encodedBytes > settings.maxOutputBytes) throw failure();
            }
          }
          return Object.freeze(entries);
        } finally {
          if (connection.usable)
            await new Promise<void>((resolve) => native.close(handle, () => resolve()));
        }
      });
    },
    async rename(name, suppliedSource, suppliedDestination, input) {
      check();
      const source = remotePath(suppliedSource),
        destination = remotePath(suppliedDestination),
        options = call(input, settings, 'rename');
      if (source === destination) throw failure();
      return launch(name, options.options, 'rename', async (connection, request) => {
        const existing = await connection.path(source, false, request),
          target = await connection.path(destination, true, request);
        if (!existing?.isFile() || (target && (!target.isFile() || options.overwrite === 'fail')))
          throw failure();
        const atomic =
          connection.native.sftp._extensions?.['posix-rename@openssh.com'] === '1' &&
          options.overwrite === 'replace';
        if ((options.requireAtomic || options.overwrite === 'replace') && !atomic)
          throw failure('EK_UNSUPPORTED_CAPABILITY');
        request.check();
        request.submitted = true;
        if (atomic) await request.wait(connection.native.posixRename(source, destination));
        else await request.wait(connection.native.rename(source, destination));
        return Object.freeze({
          source,
          destination,
          atomicity: atomic ? 'confirmed' : 'not-guaranteed',
          replaced: !!target,
        });
      });
    },
    native(name) {
      check();
      profile(name);
      const connection = connections.get(name);
      if (!connection?.usable) throw failure('EK_RESOURCE_CLOSED');
      return connection.native;
    },
  });
  const ssh = Object.freeze<SshService>({
    async exec(name, suppliedCommand, suppliedArgs, options) {
      check();
      const command = settings.commands[identifier(suppliedCommand)];
      if (!command) throw failure('EK_SSH_FORBIDDEN');
      const args = fields(suppliedArgs, command.parameters);
      if (Object.keys(args).length !== command.parameters.length) throw failure('EK_SSH_FORBIDDEN');
      const tokens = command.arguments.map((token) =>
          token.startsWith('{') ? text(args[token.slice(1, -1)], 4096, true) : token,
        ),
        rendered = quote([command.executable, ...tokens]);
      if (Buffer.byteLength(rendered) > 64 * 1024) throw failure('EK_SSH_FORBIDDEN');
      return launch(name, options, 'exec', async (connection, request) => {
        request.submitted = true;
        const channel = await request.wait(
          new Promise<ClientChannel>((resolve, reject) =>
            connection.native.client.exec(rendered, (error, channel) =>
              error ? reject(failure('EK_SFTP_TRANSFER', true)) : resolve(channel),
            ),
          ),
        );
        const stdout: Buffer[] = [],
          stderr: Buffer[] = [];
        let size = 0,
          truncated = false,
          exitCode: number | null = null;
        const collect = (target: Buffer[]) => (part: Buffer) => {
          const remaining = settings.maxOutputBytes - size;
          if (remaining > 0) {
            const copy = Buffer.from(part.subarray(0, remaining));
            target.push(copy);
            size += copy.length;
          }
          if (part.length > remaining) {
            truncated = true;
            channel.close();
          }
        };
        channel.on('data', collect(stdout));
        channel.stderr.on('data', collect(stderr));
        channel.stderr.on('error', () => request.stop('EK_SFTP_TRANSFER'));
        channel.on('exit', (code: number | null) => {
          if (Number.isInteger(code)) exitCode = code;
        });
        try {
          channel.end();
          await request.wait(
            new Promise<void>((resolve, reject) => {
              channel.once('close', () => resolve());
              channel.once('error', () => reject(failure('EK_SFTP_TRANSFER', true)));
            }),
          );
          observe.measure('command.output.bytes', size);
          return Object.freeze({
            exitCode: truncated ? null : exitCode,
            stdout: new Uint8Array(Buffer.concat(stdout)),
            stderr: new Uint8Array(Buffer.concat(stderr)),
            truncated,
          });
        } finally {
          channel.destroy();
        }
      });
    },
  });
  return {
    sftp,
    ssh,
    async init() {
      for (const profile of settings.connections)
        await launch(profile.name, undefined, 'connect', async () => undefined, true);
    },
    async close() {
      closed = true;
      for (const { request } of active.values()) request.stop('EK_ABORTED');
      for (const connection of connections.values()) connection.destroy();
      await Promise.all([...active.values()].map((task) => task.end));
      await Promise.all([...connections.values()].map((connection) => connection.closed));
    },
  };
}
