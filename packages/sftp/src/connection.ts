// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, timingSafeEqual } from 'node:crypto';
import { Socket } from 'node:net';
import type { Stats } from 'ssh2';
import type { Profile, Settings } from './settings.js';
import { remotePath, within } from './settings.js';
import { fields, failure, text } from './validation.js';
import { nativeClient } from './native.js';
import { Request } from './request.js';

export function bytes(input: unknown, maximum: number): Buffer {
  try {
    if (!(input instanceof Uint8Array)) throw failure();
    const prototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
    const get = (name: string): unknown =>
      Object.getOwnPropertyDescriptor(prototype, name)!.get!.call(input);
    const buffer = get('buffer') as ArrayBuffer,
      offset = get('byteOffset') as number,
      length = get('byteLength') as number;
    Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength')!.get!.call(buffer);
    if (length > maximum) throw failure();
    return Buffer.from(Buffer.from(buffer, offset, length));
  } catch {
    throw failure();
  }
}
/** One approved profile owns its actual SDK, TCP socket, host proof and credential lifetime. */
export class Connection {
  readonly #owned = nativeClient();
  readonly native = this.#owned.native;
  readonly socket = new Socket();
  readonly closed: Promise<void>;
  #usable = false;
  #expiry = Infinity;
  #expiryTimer: ReturnType<typeof setTimeout> | undefined;
  #hostRejected = false;
  #hostVerified = false;
  constructor(
    readonly settings: Settings,
    readonly profile: Profile,
  ) {
    this.closed = new Promise((resolve) =>
      this.socket.once('close', () => {
        this.#usable = false;
        resolve();
      }),
    );
    this.socket.on('error', () => undefined);
    this.native.client.on('close', () => this.destroy());
    this.native.client.on('error', () => this.destroy());
  }
  get usable(): boolean {
    return this.#usable && !this.socket.destroyed && Date.now() < this.#expiry;
  }
  destroy(): void {
    this.#usable = false;
    clearTimeout(this.#expiryTimer);
    this.native.client.destroy();
    this.socket.destroy();
  }
  async connect(request: Request<unknown>): Promise<void> {
    let key: Buffer | undefined;
    try {
      request.check();
      const raw = await request.wait(
          this.settings.getSecret(this.profile.privateKeyRef, {
            signal: request.controller.signal,
            timeoutMs: request.remaining(),
          }),
        ),
        value = fields(raw, ['bytes', 'keyVersion', 'expiresAt']);
      text(value.keyVersion, 256);
      if (value.expiresAt !== undefined) {
        if (
          typeof value.expiresAt !== 'string' ||
          !Number.isFinite(Date.parse(value.expiresAt)) ||
          Date.parse(value.expiresAt) <= Date.now()
        )
          throw failure();
        this.#expiry = Date.parse(value.expiresAt);
      }
      key = bytes(value.bytes, 64 * 1024);
      if (!key.length) throw failure();
      this.socket.connect({ host: this.profile.host, port: this.profile.port });
      await request.wait(
        this.#owned.connect({
          sock: this.socket,
          host: this.profile.host,
          port: this.profile.port,
          username: this.profile.username,
          privateKey: key,
          authHandler: ['publickey'],
          tryKeyboard: false,
          agentForward: false,
          readyTimeout: request.remaining(),
          algorithms: { compress: ['none'] },
          hostVerifier: (raw: Buffer) => {
            const actual = createHash('sha256').update(raw).digest();
            this.#hostVerified = this.profile.pins.some((pin) =>
              timingSafeEqual(actual, Buffer.from(pin.slice(7), 'base64')),
            );
            this.#hostRejected = !this.#hostVerified;
            return this.#hostVerified;
          },
        }),
      );
      if (!this.#hostVerified || this.socket.destroyed || Date.now() >= this.#expiry)
        throw failure();
      this.#usable = true;
      if (Number.isFinite(this.#expiry)) {
        const expire = () => {
          const remaining = this.#expiry - Date.now();
          if (remaining <= 0) this.destroy();
          else {
            this.#expiryTimer = setTimeout(expire, Math.min(remaining, 2147483647));
            this.#expiryTimer.unref();
          }
        };
        expire();
      }
    } catch {
      this.destroy();
      request.check();
      throw failure(this.#hostRejected ? 'EK_SFTP_HOSTKEY' : 'EK_SFTP_TRANSFER');
    } finally {
      key?.fill(0);
    }
  }
  async stat(path: string): Promise<Stats | undefined> {
    return new Promise((resolve, reject) =>
      this.native.sftp.lstat(path, (error, value) => {
        if (error && 'code' in error && error.code === 2) resolve(undefined);
        else if (error) reject(failure());
        else resolve(value);
      }),
    );
  }
  async path(
    path: string,
    missing: boolean,
    request: Request<unknown>,
  ): Promise<Stats | undefined> {
    if (!this.profile.roots.some((root) => within(path, root))) throw failure();
    const parts = path.split('/').filter(Boolean);
    let cursor = '',
      found: Stats | undefined;
    for (let index = -1; index < parts.length; index++) {
      request.check();
      cursor = index < 0 ? '/' : (cursor === '/' ? '/' : cursor + '/') + parts[index]!;
      found = await request.wait(this.stat(cursor));
      if (!found) {
        if (missing && index === parts.length - 1) return undefined;
        throw failure();
      }
      if (found.isSymbolicLink() || (index < parts.length - 1 && !found.isDirectory()))
        throw failure();
      const canonical = remotePath(await request.wait(this.native.realPath(cursor)));
      if (canonical !== cursor) throw failure();
    }
    return found;
  }
}
