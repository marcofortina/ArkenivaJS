// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { fork } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { ErrorCode, OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { LdapEntry, LdapGroup, LdapService, LdapUser, WorkerInput } from './contracts.js';
import type { Settings } from './settings.js';
import { query } from './settings.js';
import { fields, integer, text, failure } from './validation.js';
import { recorder } from './observation.js';
import type { Observers } from './observation.js';

const nativeErrors = new Set([
  'EK_LDAP_CONNECT',
  'EK_LDAP_BIND',
  'EK_LDAP_FILTER',
  'EK_LDAP_SEARCH',
]);
const typedArray = Object.getPrototypeOf(Uint8Array.prototype),
  byteLength = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!,
  backingBuffer = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!;

/** Establish bounds from native slots before allocation; instance metadata never runs. */
function copySecretBytes(input: unknown, maximum: number): Buffer {
  if (!types.isUint8Array(input)) throw failure('EK_LDAP_BIND');
  const length = Reflect.apply(byteLength, input, []) as number;
  if (
    length < 1 ||
    length > maximum ||
    types.isSharedArrayBuffer(Reflect.apply(backingBuffer, input, []))
  )
    throw failure('EK_LDAP_BIND');
  const owned = Buffer.alloc(length);
  Uint8Array.prototype.set.call(owned, input);
  return owned;
}
function options(input: OperationOptions | undefined, maximum: number) {
  const value = fields(input ?? {}, ['signal', 'timeoutMs']);
  let signal: AbortSignal | undefined;
  if (value.signal !== undefined) {
    try {
      signal = captureAbortSignal(value.signal);
    } catch {
      throw failure();
    }
  }
  return {
    signal,
    timeoutMs: integer(value.timeoutMs ?? maximum, maximum),
  };
}
function immutable<T>(input: T): T {
  if (input && typeof input === 'object') {
    for (const item of Object.values(input)) immutable(item);
    Object.freeze(input);
  }
  return input;
}
/** One bounded operation owns its provider work, child, sockets and physical completion. */
class Request {
  readonly controller = new AbortController();
  readonly done: Promise<void>;
  readonly #deadline: number;
  readonly #timer: ReturnType<typeof setTimeout>;
  readonly #signal: AbortSignal | undefined;
  readonly #abort: () => void;
  #child: ChildProcess | undefined;
  #error: KitError | undefined;
  #value: unknown;
  #received = false;
  #binding = false;
  #entry: LdapEntry | undefined;
  #acknowledge = false;
  #wait: (() => void) | undefined;
  #finished = false;
  #secretExpiry = Infinity;
  constructor(
    settings: Settings,
    operation: WorkerInput['operation'],
    data: Partial<WorkerInput>,
    input: OperationOptions | undefined,
    observe: ReturnType<typeof recorder>,
  ) {
    const opts = options(input, settings.timeoutMs);
    const started = performance.now();
    this.#deadline = performance.now() + opts.timeoutMs;
    this.#signal = opts.signal;
    this.#abort = () => this.stop('EK_ABORTED');
    opts.signal?.addEventListener('abort', this.#abort, { once: true });
    this.#timer = setTimeout(() => this.stop('EK_TIMEOUT'), opts.timeoutMs);
    if (opts.signal?.aborted) this.stop('EK_ABORTED');
    this.done = this.#start(settings, operation, data, observe)
      .catch((error: unknown) => {
        this.#error ??=
          error instanceof KitError ? error : failure('EK_LDAP_CONNECT', this.#binding);
      })
      .finally(() => {
        clearTimeout(this.#timer);
        this.#signal?.removeEventListener('abort', this.#abort);
        this.#finished = true;
        this.#wait?.();
        observe.complete(
          operation,
          this.#error?.code === 'EK_TIMEOUT' ? 'timeout' : this.#error ? 'error' : 'ok',
          Math.max(0, performance.now() - started),
        );
      });
  }
  check(): void {
    if (this.#error) throw this.#error;
    if (this.controller.signal.aborted) throw failure('EK_ABORTED', this.#binding);
    if (performance.now() >= this.#deadline) throw failure('EK_TIMEOUT', this.#binding);
    if (Date.now() >= this.#secretExpiry) throw failure('EK_LDAP_BIND');
  }
  stop(code: ErrorCode): void {
    this.#error ??= failure(code, this.#binding);
    this.controller.abort();
    this.#child?.kill('SIGKILL');
    this.#wait?.();
  }
  async #secret(settings: Settings, reference: string, maximum: number): Promise<string> {
    this.check();
    let raw: unknown;
    try {
      raw = await settings.getSecret(reference, {
        signal: this.controller.signal,
        timeoutMs: Math.max(1, Math.ceil(this.#deadline - performance.now())),
      });
    } catch {
      this.check();
      throw failure('EK_LDAP_BIND');
    }
    this.check();
    const value = fields(raw, ['bytes', 'keyVersion', 'expiresAt']);
    text(value.keyVersion, 256);
    if (
      value.expiresAt !== undefined &&
      (typeof value.expiresAt !== 'string' ||
        !Number.isFinite(Date.parse(value.expiresAt)) ||
        Date.parse(value.expiresAt) <= Date.now())
    )
      throw failure('EK_LDAP_BIND');
    if (typeof value.expiresAt === 'string')
      this.#secretExpiry = Math.min(this.#secretExpiry, Date.parse(value.expiresAt));
    const owned = copySecretBytes(value.bytes, maximum);
    try {
      return text(new TextDecoder('utf-8', { fatal: true }).decode(owned), maximum);
    } finally {
      owned.fill(0);
    }
  }
  async #start(
    settings: Settings,
    operation: WorkerInput['operation'],
    data: Partial<WorkerInput>,
    observe: ReturnType<typeof recorder>,
  ): Promise<void> {
    const bindDn = await this.#secret(settings, settings.bindDnRef, 2048),
      bindPassword = await this.#secret(settings, settings.bindPasswordRef, 16384);
    const ca =
      settings.caRef === undefined
        ? undefined
        : await this.#secret(settings, settings.caRef, 262144);
    this.check();
    const child = fork(new URL('./worker.js', import.meta.url), [], {
      execPath: process.execPath,
      execArgv: ['--max-old-space-size=64', '--max-semi-space-size=8'],
      // In particular, NODE_DEBUG=ldapts can expose native bind messages and is never inherited.
      env: { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'production', UV_THREADPOOL_SIZE: '1' },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      serialization: 'advanced',
    });
    this.#child = child;
    const completed = new Promise<void>((resolve) => {
      child.on('error', () => this.stop('EK_LDAP_CONNECT'));
      child.on('message', (raw: unknown) => {
        if (this.controller.signal.aborted) return;
        try {
          this.check();
          const message = fields(raw, ['type', 'entry', 'value', 'kind', 'name']);
          if (
            message.type === 'measure' &&
            ['bind', 'search', 'depth'].includes(message.name as string) &&
            typeof message.value === 'number' &&
            Number.isFinite(message.value) &&
            message.value >= 0 &&
            message.value <= 30000
          ) {
            observe.measure(message.name as 'bind' | 'search' | 'depth', message.value);
            return;
          }
          if (message.type === 'binding') {
            this.#binding = true;
            return;
          }
          if (
            message.type === 'entry' &&
            operation === 'search' &&
            !this.#entry &&
            !this.#received
          ) {
            this.#entry = immutable(message.entry as LdapEntry);
            this.#wait?.();
            return;
          }
          if (message.type === 'result' && !this.#received) {
            this.#received = true;
            this.#value = immutable(message.value);
            return;
          }
          if (message.type === 'error' && nativeErrors.has(message.kind as string)) {
            this.stop(message.kind as ErrorCode);
            return;
          }
          throw failure('EK_LDAP_SEARCH');
        } catch {
          this.stop('EK_LDAP_SEARCH');
        }
      });
      child.once('close', (code) => {
        if (code !== 0 || !this.#received)
          this.#error ??= failure('EK_LDAP_CONNECT', this.#binding);
        resolve();
      });
    });
    try {
      this.check();
      child.send(
        {
          operation,
          url: settings.url,
          startTls: settings.startTls,
          bindDn,
          bindPassword,
          ...(ca === undefined ? {} : { ca }),
          baseDn: settings.baseDn,
          groupBase: settings.groupBase,
          template: settings.template,
          allowedAttributes: settings.allowedAttributes,
          maxEntries: settings.maxEntries,
          maxDepth: settings.maxDepth,
          timeoutMs: Math.max(1, Math.ceil(this.#deadline - performance.now())),
          ...data,
        },
        (error) => {
          if (error) this.stop('EK_LDAP_CONNECT');
        },
      );
    } catch {
      this.stop('EK_LDAP_CONNECT');
    }
    await completed;
    this.check();
  }
  async result<T>(): Promise<T> {
    while (!this.#finished && !this.#error)
      await new Promise<void>((resolve) => {
        this.#wait = resolve;
      });
    this.check();
    return this.#value as T;
  }
  async next(): Promise<IteratorResult<LdapEntry>> {
    this.check();
    if (this.#acknowledge) {
      this.#acknowledge = false;
      this.#child?.send({ type: 'ack' }, (error) => {
        if (error) this.stop('EK_LDAP_CONNECT');
      });
    }
    while (!this.#entry && !this.#finished && !this.#error)
      await new Promise<void>((resolve) => {
        this.#wait = resolve;
      });
    this.check();
    if (this.#entry) {
      const entry = this.#entry;
      this.#entry = undefined;
      this.#acknowledge = true;
      return { value: entry, done: false };
    }
    return { value: undefined, done: true };
  }
}

export function managedService(
  settings: Settings,
  applicationSignal?: AbortSignal,
  ready: () => boolean = () => true,
  observers: Observers = {},
) {
  const active = new Set<Request>();
  let closed = false;
  const observe = recorder(observers);
  const begin = (
    operation: WorkerInput['operation'],
    data: Partial<WorkerInput>,
    opts?: OperationOptions,
  ) => {
    if (closed || !ready()) throw failure('EK_RESOURCE_CLOSED');
    if (active.size >= 4) throw failure('EK_BACKEND_UNAVAILABLE');
    const request = new Request(settings, operation, data, opts, observe);
    active.add(request);
    void request.done.finally(() => active.delete(request));
    return request;
  };
  const username = (input: unknown) => text(fields(input, ['username']).username, 2048);
  const service = Object.freeze<LdapService>({
    findUser: (input, opts) => {
      const name = username(input);
      return begin('find', { username: name }, opts).result<LdapUser | null>();
    },
    getGroups: (input, opts) =>
      begin('groups', { userDn: text(input, 2048) }, opts).result<readonly LdapGroup[]>(),
    verifyCredentials: async (input, password, opts) => {
      const name = username(input),
        operation = options(opts, settings.timeoutMs);
      if (operation.signal?.aborted) throw failure('EK_ABORTED');
      if (closed || !ready()) throw failure('EK_RESOURCE_CLOSED');
      if (typeof password !== 'string') throw failure();
      if (!password || password.includes('\0')) return false;
      return begin(
        'verify',
        { username: name, password: text(password, 16384) },
        opts,
      ).result<boolean>();
    },
    ping: (opts) => begin('ping', {}, opts).result<boolean>(),
    search: (input, opts) => {
      const captured = query(input, settings);
      options(opts, settings.timeoutMs);
      let request: Request | undefined,
        started = false,
        ended = false,
        pending = false;
      return {
        [Symbol.asyncIterator]() {
          if (started) throw failure('EK_RESOURCE_CLOSED');
          started = true;
          return {
            async next(): Promise<IteratorResult<LdapEntry>> {
              if (pending) throw failure('EK_BACKEND_UNAVAILABLE');
              if (ended) return { done: true, value: undefined };
              pending = true;
              try {
                request ??= begin('search', { query: captured }, opts);
                const result = await request.next();
                if (result.done) ended = true;
                return result;
              } catch (error) {
                ended = true;
                request?.stop('EK_ABORTED');
                throw error;
              } finally {
                pending = false;
              }
            },
            async return(): Promise<IteratorResult<LdapEntry>> {
              ended = true;
              request?.stop('EK_ABORTED');
              await request?.done;
              return { done: true, value: undefined };
            },
          };
        },
      };
    },
  });
  const abort = () => {
    closed = true;
    for (const request of active) request.stop('EK_RESOURCE_CLOSED');
  };
  applicationSignal?.addEventListener('abort', abort, { once: true });
  if (applicationSignal?.aborted) abort();
  return {
    service,
    async close() {
      abort();
      applicationSignal?.removeEventListener('abort', abort);
      await Promise.all([...active].map((request) => request.done));
    },
  };
}
