// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Agent, request as nativeRequest } from 'node:https';
import type { RequestOptions } from 'node:https';
import type { IncomingMessage } from 'node:http';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { toUSVString, types } from 'node:util';
import { performance } from 'node:perf_hooks';
import { Axios, AxiosHeaders, isAxiosError } from 'axios';
import type { AxiosResponse } from 'axios';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import { inspectXml } from './xml.js';
import { failure } from './validation.js';

export interface WireProfile {
  readonly endpoint: string;
  readonly protocol: '1.1' | '1.2';
  readonly timeoutMs: number;
  readonly maxConcurrent: number;
  readonly maxInputBytes: number;
  readonly maxResponseBytes: number;
}
export interface TlsMaterial {
  readonly ca?: Uint8Array;
  readonly cert?: Uint8Array;
  readonly key?: Uint8Array;
  readonly passphrase?: string;
  readonly authorization?: string;
}
export interface WireReply {
  readonly body: string;
  readonly response: AxiosResponse<Buffer>;
}
const positive = (value: number, maximum: number) =>
  Number.isSafeInteger(value) && value >= 1 && value <= maximum;
const typedArray = Object.getPrototypeOf(Uint8Array.prototype),
  bufferGetter = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!,
  offsetGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset')!.get!,
  lengthGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
function materialBytes(value: unknown): Buffer | undefined {
  if (value === undefined) return undefined;
  if (!types.isUint8Array(value)) throw failure('EK_CONFIG_INVALID');
  const buffer = bufferGetter.call(value) as ArrayBuffer,
    offset = offsetGetter.call(value) as number,
    length = lengthGetter.call(value) as number;
  if (types.isSharedArrayBuffer(buffer) || !positive(length, 1048576))
    throw failure('EK_CONFIG_INVALID');
  return Buffer.from(new Uint8Array(buffer, offset, length));
}

/** Own one fixed HTTPS destination, immutable DNS answers and finite physical request reservations. */
export class HttpsConnection {
  private readonly client = new Axios({ adapter: 'http' });
  private readonly controller = new AbortController();
  private readonly pending = new Set<Promise<unknown>>();
  private closed = false;
  private closing: Promise<void> | undefined;
  private constructor(
    readonly profile: WireProfile,
    private readonly addresses: readonly { address: string; family: 4 | 6 }[],
  ) {}
  static async create(profile: WireProfile, signal: AbortSignal): Promise<HttpsConnection> {
    const started = performance.now();
    profile = Object.freeze({ ...profile });
    let endpoint: URL;
    try {
      endpoint = new URL(profile.endpoint);
      if (
        endpoint.protocol !== 'https:' ||
        endpoint.username ||
        endpoint.password ||
        endpoint.search ||
        endpoint.hash ||
        profile.endpoint.length > 2048 ||
        !['1.1', '1.2'].includes(profile.protocol) ||
        !positive(profile.timeoutMs, 60000) ||
        !positive(profile.maxConcurrent, 8) ||
        !positive(profile.maxInputBytes, 8388608) ||
        !positive(profile.maxResponseBytes, 8388608)
      )
        throw failure('EK_CONFIG_INVALID');
    } catch {
      throw failure('EK_CONFIG_INVALID');
    }
    if (signal.aborted) throw failure('EK_ABORTED');
    if (performance.now() - started > profile.timeoutMs) throw failure('EK_TIMEOUT');
    const hostname = endpoint.hostname.replace(/^\[|\]$/g, '');
    let answers: readonly { address: string; family: number }[];
    try {
      answers = isIP(hostname)
        ? [{ address: hostname, family: isIP(hostname) }]
        : await lookup(hostname, { all: true, verbatim: true });
    } catch (error) {
      throw failure(
        error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)
          ? error.code
          : 'EK_BACKEND_UNAVAILABLE',
      );
    }
    if (
      !answers.length ||
      answers.length > 16 ||
      answers.some((entry) => !isIP(entry.address) || isIP(entry.address) !== entry.family)
    )
      throw failure('EK_BACKEND_UNAVAILABLE');
    if (signal.aborted) throw failure('EK_ABORTED');
    if (performance.now() - started > profile.timeoutMs) throw failure('EK_TIMEOUT');
    return new HttpsConnection(
      Object.freeze({ ...profile, endpoint: endpoint.href }),
      Object.freeze(
        answers.map((entry) =>
          Object.freeze({ address: entry.address, family: entry.family as 4 | 6 }),
        ),
      ),
    );
  }
  async request(
    body: string,
    inputHeaders: Readonly<Record<string, string>>,
    material: TlsMaterial,
    options?: OperationOptions,
  ): Promise<WireReply> {
    if (this.closed) throw failure('EK_RESOURCE_CLOSED');
    const started = performance.now(),
      cancellation = new AbortController();
    let timedOut = false;
    const timeoutMs = options?.timeoutMs ?? this.profile.timeoutMs;
    if (!positive(timeoutMs, this.profile.timeoutMs)) throw failure('EK_CONFIG_INVALID');
    const signal = AbortSignal.any([
      this.controller.signal,
      cancellation.signal,
      ...(options?.signal === undefined ? [] : [captureAbortSignal(options.signal)]),
    ]);
    if (signal.aborted) throw failure('EK_ABORTED');
    if (this.pending.size >= this.profile.maxConcurrent) throw failure('EK_BACKEND_UNAVAILABLE');
    if (
      typeof body !== 'string' ||
      body.length > this.profile.maxInputBytes ||
      Buffer.byteLength(body) > this.profile.maxInputBytes ||
      toUSVString(body) !== body
    )
      throw failure('EK_SOAP_SCHEMA');
    try {
      const root = inspectXml(body, this.profile.maxInputBytes).root;
      if (
        root.local !== 'Envelope' ||
        root.uri !==
          (this.profile.protocol === '1.1'
            ? 'http://schemas.xmlsoap.org/soap/envelope/'
            : 'http://www.w3.org/2003/05/soap-envelope')
      )
        throw failure();
    } catch {
      throw failure('EK_SOAP_SCHEMA');
    }
    const headers = new AxiosHeaders();
    for (const [name, value] of Object.entries(inputHeaders)) {
      if (
        !['content-type', 'soapaction'].includes(name.toLowerCase()) ||
        typeof value !== 'string' ||
        value.length > 4096 ||
        /[\r\n\0]/.test(value)
      )
        throw failure('EK_CONFIG_INVALID');
      headers.set(name, value);
    }
    if ((material.cert === undefined) !== (material.key === undefined))
      throw failure('EK_CONFIG_INVALID');
    if (material.authorization !== undefined) {
      if (
        !/^(Basic|Bearer) [A-Za-z0-9+/=._~-]+$/.test(material.authorization) ||
        material.authorization.length > 8192
      )
        throw failure('EK_CONFIG_INVALID');
      headers.set('Authorization', material.authorization);
    }
    const ca = materialBytes(material.ca),
      cert = materialBytes(material.cert),
      privateKey = materialBytes(material.key);
    if (
      material.passphrase !== undefined &&
      (typeof material.passphrase !== 'string' ||
        material.passphrase.length > 4096 ||
        toUSVString(material.passphrase) !== material.passphrase)
    ) {
      privateKey?.fill(0);
      throw failure('EK_CONFIG_INVALID');
    }
    if (performance.now() - started >= timeoutMs) {
      privateKey?.fill(0);
      throw failure('EK_TIMEOUT');
    }
    const addresses = this.addresses,
      selected = addresses[0]!;
    const agent = new Agent({
      keepAlive: false,
      maxSockets: 1,
      maxTotalSockets: 1,
      minVersion: 'TLSv1.2',
      rejectUnauthorized: true,
      autoSelectFamily: true,
      ...(ca === undefined ? {} : { ca }),
      ...(cert === undefined ? {} : { cert, key: privateKey }),
      ...(material.passphrase === undefined ? {} : { passphrase: material.passphrase }),
      lookup(_hostname, options, callback) {
        if (options.all) callback(null, [...addresses]);
        else callback(null, selected.address, selected.family);
      },
    });
    const timer = setTimeout(
      () => {
        timedOut = true;
        cancellation.abort();
      },
      Math.max(1, Math.ceil(timeoutMs - (performance.now() - started))),
    );
    const sockets: Promise<void>[] = [];
    const transport = {
      request(options: RequestOptions, callback: (response: IncomingMessage) => void) {
        const request = nativeRequest(options, callback);
        request.on('socket', (socket) => {
          sockets.push(new Promise<void>((resolve) => socket.once('close', () => resolve())));
        });
        return request;
      },
    };
    let submitted = false;
    const task = Promise.resolve()
      .then(async () => {
        if (signal.aborted) throw failure('EK_ABORTED');
        submitted = true;
        const response = await this.client.request<Buffer>({
          url: this.profile.endpoint,
          method: 'POST',
          data: body,
          headers,
          signal,
          timeout: timeoutMs,
          httpsAgent: agent,
          proxy: false,
          maxRedirects: 0,
          decompress: false,
          responseType: 'arraybuffer',
          maxBodyLength: this.profile.maxInputBytes,
          maxContentLength: this.profile.maxResponseBytes,
          validateStatus: () => true,
          transport,
        });
        if (signal.aborted) throw failure('EK_ABORTED');
        if (performance.now() - started > timeoutMs) throw failure('EK_TIMEOUT');
        if (response.status >= 300 && response.status < 400) throw failure('EK_SOAP_SCHEMA');
        if (!Buffer.isBuffer(response.data) || response.data.length > this.profile.maxResponseBytes)
          throw failure('EK_SOAP_SCHEMA');
        const contentType: unknown = response.headers['content-type'];
        if (
          typeof contentType !== 'string' ||
          !(
            this.profile.protocol === '1.1'
              ? /^text\/xml(?:\s*;|$)/i
              : /^application\/soap\+xml(?:\s*;|$)/i
          ).test(contentType)
        )
          throw failure('EK_SOAP_SCHEMA');
        const text = response.data.toString('utf8');
        if (!Buffer.from(text).equals(response.data)) throw failure('EK_SOAP_SCHEMA');
        return { body: text, response };
      })
      .finally(async () => {
        agent.destroy();
        await Promise.all(sockets);
        privateKey?.fill(0);
      });
    this.pending.add(task);
    try {
      return await task;
    } catch (error) {
      let code: import('@arkenivajs/core').ErrorCode = 'EK_BACKEND_UNAVAILABLE';
      if (timedOut) code = 'EK_TIMEOUT';
      else if (signal.aborted) code = 'EK_ABORTED';
      else if (error instanceof KitError) code = error.code;
      else if (isAxiosError(error) && error.code === 'ERR_BAD_RESPONSE') code = 'EK_SOAP_SCHEMA';
      else if (performance.now() - started >= timeoutMs) code = 'EK_TIMEOUT';
      const safe = failure(code);
      if (!submitted) throw safe;
      throw new KitError({
        code: safe.code,
        message: safe.message,
        details: { outcome: 'unknown' },
      });
    } finally {
      clearTimeout(timer);
      this.pending.delete(task);
    }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    this.controller.abort();
    this.closing = Promise.allSettled([...this.pending]).then(() => undefined);
    return this.closing;
  }
}
