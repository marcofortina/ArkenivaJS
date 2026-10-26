// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import { createConnection } from 'node:net';
import type { Socket } from 'node:net';
import { Readable } from 'node:stream';
import { isUtf8 } from 'node:buffer';
import nodemailer from 'nodemailer';
import type { SMTPPoolOptions, SMTPPoolSentMessageInfo, Transporter } from 'nodemailer';
import { KitError } from '@arkenivajs/core';
import { within } from '@arkenivajs/core/support';
import { failure, fields, bytes, text } from './settings.js';
import type { Captured, FailureCode, operation } from './settings.js';
import type { BinaryInput, MailTransportProfile } from './contracts.js';

type Pool = Transporter<SMTPPoolSentMessageInfo, SMTPPoolOptions>;
type Policy = ReturnType<typeof operation>;
interface Credentials {
  readonly user: string;
  readonly pass: string;
  readonly version: string;
}
export interface Lane {
  current: Job | undefined;
  task: Promise<unknown> | undefined;
  pool: Pool | undefined;
  profile: string | undefined;
  credentials: Credentials | undefined;
  generation: symbol | undefined;
  timeoutMs: number | undefined;
  readonly sockets: Map<Socket, Promise<void>>;
}
/** A public waiter can expire while its private tasks still retain finite physical admission. */
export class Job {
  readonly controller = new AbortController();
  readonly pending = new Set<Promise<unknown>>();
  readonly streams = new Set<Readable>();
  readonly deadline: number;
  readonly #timer: ReturnType<typeof setTimeout>;
  readonly #abort = () => this.cancel('EK_ABORTED');
  error: FailureCode | undefined;
  attachmentBytes = 0;
  inputBytes = 0;
  outputBytes = 0;
  sendStarted = false;
  finishing = false;
  outcome: 'ok' | 'partial' | 'rejected' | 'error' = 'error';
  errorClass:
    | 'none'
    | 'config'
    | 'connection'
    | 'tls'
    | 'auth'
    | 'envelope'
    | 'message'
    | 'stream'
    | 'timeout'
    | 'cancelled'
    | 'closed'
    | 'other' = 'none';
  accepted = 0;
  rejected = 0;
  constructor(
    readonly policy: Policy,
    readonly lane: Lane,
  ) {
    this.deadline = performance.now() + policy.timeoutMs;
    this.#timer = setTimeout(() => this.cancel('EK_TIMEOUT'), policy.timeoutMs);
    policy.signal?.addEventListener('abort', this.#abort, { once: true });
    if (policy.signal?.aborted) this.cancel('EK_ABORTED');
  }
  check() {
    if (!this.error && performance.now() >= this.deadline) this.cancel('EK_TIMEOUT');
    if (this.error) throw failure(this.error, this.sendStarted);
  }
  track<T>(task: Promise<T>): Promise<T> {
    this.pending.add(task);
    void task.then(
      () => this.pending.delete(task),
      () => this.pending.delete(task),
    );
    return task;
  }
  own(stream: Readable): Readable {
    this.streams.add(stream);
    this.track(
      new Promise<void>((resolve) => {
        stream.once('close', () => {
          this.streams.delete(stream);
          resolve();
        });
      }),
    );
    return stream;
  }
  async wait<T>(task: Promise<T>): Promise<T> {
    this.track(task);
    this.check();
    try {
      const result = await within(() => task, {
        signal: this.controller.signal,
        timeoutMs: Math.max(1, Math.ceil(this.deadline - performance.now())),
      });
      this.check();
      return result;
    } catch (cause) {
      this.check();
      throw cause;
    }
  }
  cancel(code: FailureCode) {
    if (this.error) return;
    this.error = code;
    if (code === 'EK_ABORTED') this.errorClass = 'cancelled';
    else if (code === 'EK_TIMEOUT') this.errorClass = 'timeout';
    else if (code === 'EK_RESOURCE_CLOSED') this.errorClass = 'closed';
    else if (code === 'EK_MAIL_CONFIG') this.errorClass = 'config';
    else if (this.errorClass === 'none') this.errorClass = 'other';
    this.controller.abort();
    for (const stream of this.streams) stream.destroy();
    this.track(retire(this.lane));
  }
  async finish() {
    this.finishing = true;
    clearTimeout(this.#timer);
    this.policy.signal?.removeEventListener('abort', this.#abort);
    for (const stream of this.streams) stream.destroy();
    this.streams.clear();
    while (this.pending.size) await Promise.allSettled([...this.pending]);
  }
}
/** Kill only this lane's sockets; an active send is never requeued into another lane. */
export async function retire(lane: Lane): Promise<void> {
  lane.generation = undefined;
  lane.pool?.close();
  lane.pool = undefined;
  lane.profile = undefined;
  lane.credentials = undefined;
  lane.timeoutMs = undefined;
  const closed = [...lane.sockets.values()];
  for (const socket of lane.sockets.keys()) socket.destroy();
  await Promise.all(closed);
}
export function lanes(count: number): Lane[] {
  return Array.from({ length: count }, () => ({
    current: undefined,
    task: undefined,
    pool: undefined,
    profile: undefined,
    credentials: undefined,
    generation: undefined,
    timeoutMs: undefined,
    sockets: new Map(),
  }));
}
export async function credentials(settings: Captured, job: Job): Promise<Credentials | undefined> {
  const profile = job.policy.profile;
  if (!profile.usernameRef || !profile.passwordRef) return undefined;
  const read = async (reference: string) => {
    job.check();
    const value = fields(
        await job.wait(
          Promise.resolve().then(() => {
            job.check();
            return settings.getSecret(reference, {
              signal: job.controller.signal,
              timeoutMs: Math.max(1, Math.ceil(job.deadline - performance.now())),
            });
          }),
        ),
        ['bytes', 'keyVersion', 'expiresAt'],
      ),
      secret = bytes(value.bytes, 65536);
    try {
      const version = text(value.keyVersion, 128, true);
      if (!secret.byteLength || !isUtf8(secret) || secret.includes(0))
        throw failure('EK_MAIL_CONFIG');
      if (value.expiresAt !== undefined) {
        const expires = Date.parse(text(value.expiresAt, 64, true));
        if (!Number.isFinite(expires) || expires <= Date.now()) throw failure('EK_MAIL_CONFIG');
      }
      return {
        value: Buffer.from(secret.buffer, secret.byteOffset, secret.byteLength).toString('utf8'),
        version,
      };
    } finally {
      secret.fill(0);
    }
  };
  const user = await read(profile.usernameRef),
    pass = await read(profile.passwordRef);
  return { user: user.value, pass: pass.value, version: user.version + '\u0000' + pass.version };
}
/** Reuse one native SMTP pool per admitted lane with no hidden application queue. */
export async function pool(
  lane: Lane,
  profile: MailTransportProfile,
  auth: Credentials | undefined,
  job: Job,
): Promise<Pool> {
  job.check();
  if (
    lane.pool &&
    lane.profile === profile.name &&
    lane.timeoutMs === job.policy.timeoutMs &&
    lane.credentials?.version === auth?.version &&
    lane.credentials?.user === auth?.user &&
    lane.credentials?.pass === auth?.pass
  )
    return lane.pool;
  await retire(lane);
  job.check();
  const generation = Symbol('mail.pool');
  lane.generation = generation;
  const options: SMTPPoolOptions & { pool: true } = {
    host: profile.host,
    port: profile.port,
    secure: profile.port === 465,
    requireTLS: true,
    ignoreTLS: false,
    opportunisticTLS: false,
    tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' },
    pool: true,
    maxConnections: 1,
    maxMessages: 100,
    maxRequeues: 0,
    idleTimeout: 30000,
    connectionTimeout: job.policy.timeoutMs,
    greetingTimeout: job.policy.timeoutMs,
    socketTimeout: job.policy.timeoutMs,
    maxResponseSize: 65536,
    logger: false,
    debug: false,
    disableFileAccess: true,
    disableUrlAccess: true,
    ...(auth ? { auth: { user: auth.user, pass: auth.pass } } : {}),
    getSocket(_options, done) {
      const owner = lane.current;
      if (!owner || owner.error || lane.generation !== generation) {
        done(failure('EK_RESOURCE_CLOSED'));
        return;
      }
      try {
        owner.check();
      } catch {
        done(failure('EK_TIMEOUT'));
        return;
      }
      const opening = (async () => {
        // Do not overlap a replacement with a previous socket still closing in the native pool.
        const closed = [...lane.sockets.values()];
        for (const socket of lane.sockets.keys()) socket.destroy();
        await owner.wait(Promise.all(closed));
        owner.check();
        const socket = createConnection({ host: profile.host, port: profile.port });
        let settled = false;
        lane.sockets.set(
          socket,
          new Promise<void>((resolve) =>
            socket.once('close', () => {
              lane.sockets.delete(socket);
              resolve();
            }),
          ),
        );
        socket.once('connect', () => {
          if (!settled) {
            settled = true;
            done(null, { connection: socket, secured: false });
          }
        });
        socket.on('error', () => {
          if (!owner.error) owner.errorClass = 'connection';
          if (!settled) {
            settled = true;
            done(failure('EK_MAIL_SEND'));
          }
        });
        socket.once('close', () => {
          if (!settled) {
            settled = true;
            done(failure(owner.error ?? 'EK_MAIL_SEND'));
          }
        });
        socket.setTimeout(Math.max(1, Math.ceil(owner.deadline - performance.now())), () =>
          socket.destroy(failure('EK_TIMEOUT')),
        );
      })().catch(() => done(failure(owner.error ?? 'EK_MAIL_SEND')));
      owner.track(opening);
    },
  };
  lane.pool = nodemailer.createTransport(options);
  lane.profile = profile.name;
  lane.credentials = auth;
  lane.timeoutMs = job.policy.timeoutMs;
  return lane.pool;
}
/** Convert an explicit attachment source into a bounded owned Node stream. */
export function attachment(input: BinaryInput, job: Job, settings: Captured): Readable {
  const source =
    input.bytes === undefined
      ? input.stream!
      : (async function* () {
          yield input.bytes!;
        })();
  const iterator = source[Symbol.asyncIterator]();
  let ended = false;
  const stream = Readable.from(
    (async function* () {
      try {
        while (true) {
          job.check();
          const next = await job.wait(
            Promise.resolve().then(() => {
              job.check();
              return iterator.next();
            }),
          );
          if (next.done) {
            ended = true;
            return;
          }
          const value = bytes(
            next.value,
            Math.min(
              job.policy.profile.maxAttachmentBytes - job.attachmentBytes,
              settings.maxInputBytes - job.inputBytes,
            ),
          );
          job.attachmentBytes += value.byteLength;
          job.inputBytes += value.byteLength;
          for (let offset = 0; offset < value.byteLength; offset += 16384) {
            job.check();
            yield Buffer.from(value.slice(offset, offset + 16384));
          }
        }
      } finally {
        if (!ended && iterator.return) {
          ended = true;
          job.track(Promise.resolve().then(() => iterator.return!()));
        }
      }
    })(),
    { objectMode: false, highWaterMark: 16384 },
  );
  stream.on('error', () => {
    if (!job.finishing) {
      job.errorClass = 'stream';
      job.cancel('EK_MAIL_SEND');
    }
  });
  job.own(stream);
  return stream;
}
export function safeFailure(cause: unknown, job: Job): KitError {
  if (job.error) return failure(job.error, job.sendStarted);
  try {
    if (cause instanceof KitError && ['EK_MAIL_CONFIG', 'EK_MAIL_REJECTED'].includes(cause.code))
      return failure(cause.code as FailureCode, job.sendStarted);
  } catch {
    /* An untrusted provider exception cannot escape the safe error boundary. */
  }
  return failure('EK_MAIL_SEND', job.sendStarted);
}
/** Reduce native diagnostics to a closed catalog without retaining any server response or address. */
export function classify(cause: unknown, job: Job): void {
  if (job.error) return;
  try {
    const code =
      cause && typeof cause === 'object'
        ? Object.getOwnPropertyDescriptor(cause, 'code')?.value
        : undefined;
    const catalog: Record<string, Job['errorClass']> = {
      ETLS: 'tls',
      EREQUIRETLS: 'tls',
      EAUTH: 'auth',
      ENOAUTH: 'auth',
      EENVELOPE: 'envelope',
      EMESSAGE: 'message',
      ESTREAM: 'stream',
      ECONNECTION: 'connection',
      ESOCKET: 'connection',
      EDNS: 'connection',
      ETIMEDOUT: 'timeout',
    };
    job.errorClass =
      typeof code === 'string' && Object.hasOwn(catalog, code) ? catalog[code]! : 'other';
  } catch {
    job.errorClass = 'other';
  }
}
