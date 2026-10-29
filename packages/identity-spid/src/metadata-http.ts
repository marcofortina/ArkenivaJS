// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder } from 'node:util';
import { decodeProtectedHeader } from 'jose';
import { KitError } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { OperationOptions } from '@arkenivajs/core';
import { createHttpClient } from '@arkenivajs/http';
import type { ManagedHttpClient } from '@arkenivajs/http';
import type { BoundedRuntimePolicy, FederationMetadataPolicy } from './contracts.js';
import { failure, fields, integer, url } from './validation.js';

function transportFailure(error: unknown): KitError {
  if (error instanceof KitError && error.code === 'EK_BACKEND_UNAVAILABLE')
    return new KitError({
      code: error.code,
      message: 'The federation metadata request capacity is unavailable',
    });
  if (
    error instanceof KitError &&
    ['EK_TIMEOUT', 'EK_ABORTED', 'EK_RESOURCE_CLOSED'].includes(error.code)
  )
    return new KitError({
      code: error.code,
      message:
        error.code === 'EK_TIMEOUT'
          ? 'The federation request exceeded its deadline'
          : error.code === 'EK_ABORTED'
            ? 'The federation request was canceled'
            : 'The federation metadata transport is closed',
    });
  return failure('EK_EID_FEDERATION');
}

/** Federation documents use the existing bounded HTTP client with exact endpoint approval. */
export class FederationHttp {
  private readonly client: ManagedHttpClient;
  private readonly endpoints: ReadonlySet<string>;
  private readonly maximum: number;
  private readonly timeout: number;
  private readonly inputMaximum: number;
  private readonly capacity: number;
  private active = 0;
  constructor(
    metadata: Pick<FederationMetadataPolicy, 'approvedMetadataEndpoints' | 'maxBytes'>,
    policy: BoundedRuntimePolicy,
    environment: 'production' | 'development' | 'test',
  ) {
    try {
      if (!['production', 'development', 'test'].includes(environment)) throw failure();
      this.endpoints = new Set(
        metadata.approvedMetadataEndpoints.map((endpoint) => new URL(url(endpoint)).href),
      );
      if (!this.endpoints.size || this.endpoints.size !== metadata.approvedMetadataEndpoints.length)
        throw failure();
      this.maximum = Math.min(
        integer(metadata.maxBytes),
        policy.maxOutputBytes === undefined ? Infinity : integer(policy.maxOutputBytes),
      );
      this.inputMaximum = Math.min(
        integer(metadata.maxBytes),
        policy.maxInputBytes === undefined ? Infinity : integer(policy.maxInputBytes),
      );
      this.timeout = integer(policy.timeoutMs);
      this.capacity = integer(policy.maxConcurrent);
      this.client = createHttpClient({
        allowedOrigins: [
          ...new Set([...this.endpoints].map((endpoint) => new URL(endpoint).origin)),
        ],
        allowPrivateNetwork: environment === 'test',
        maxResponseBytes: this.maximum,
        timeoutMs: this.timeout,
        connections: Math.min(64, this.capacity),
        retry: { attempts: 1 },
      });
    } catch {
      throw failure();
    }
  }
  private options(input?: OperationOptions): OperationOptions {
    const value = fields(input ?? {}, ['signal', 'timeoutMs']);
    return {
      timeoutMs:
        value.timeoutMs === undefined
          ? this.timeout
          : Math.min(this.timeout, integer(value.timeoutMs)),
      ...(value.signal === undefined ? {} : { signal: captureAbortSignal(value.signal) }),
    };
  }
  private endpoint(input: string): URL {
    const target = new URL(url(input));
    if (!this.endpoints.has(target.href)) throw failure('EK_EID_FEDERATION');
    return target;
  }
  private async read(
    target: URL,
    type: string,
    body: string | undefined,
    options?: OperationOptions,
  ): Promise<string> {
    let retained = false;
    try {
      if (
        Buffer.byteLength(target.href) > this.inputMaximum ||
        (body !== undefined && Buffer.byteLength(body) > this.inputMaximum)
      )
        throw failure('EK_EID_FEDERATION');
      const selected = this.options(options);
      if (this.active >= this.capacity)
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'The federation metadata request capacity is exhausted',
        });
      this.active++;
      retained = true;
      const response = await this.client.request(target.href, {
        method: body === undefined ? 'GET' : 'POST',
        headers: {
          accept: type,
          ...(body === undefined ? {} : { 'content-type': 'application/x-www-form-urlencoded' }),
        },
        ...(body === undefined ? {} : { body }),
        ...selected,
      });
      if (
        response.status !== 200 ||
        response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase() !== type
      )
        throw failure('EK_EID_FEDERATION');
      const bytes = await response.arrayBuffer();
      if (!bytes.byteLength || bytes.byteLength > this.maximum) throw failure('EK_EID_FEDERATION');
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (error) {
      throw transportFailure(error);
    } finally {
      if (retained) this.active--;
    }
  }
  async statement(endpoint: string, subject?: string, options?: OperationOptions): Promise<string> {
    try {
      const target = this.endpoint(endpoint);
      if (subject !== undefined) {
        if (target.searchParams.has('sub')) throw failure('EK_EID_FEDERATION');
        target.searchParams.set('sub', url(subject));
      }
      return await this.read(target, 'application/entity-statement+jwt', undefined, options);
    } catch (error) {
      throw transportFailure(error);
    }
  }
  async trustMarkStatus(
    endpoint: string,
    trustMark: string,
    options?: OperationOptions,
  ): Promise<string> {
    try {
      if (
        typeof trustMark !== 'string' ||
        Buffer.byteLength(trustMark) > this.inputMaximum ||
        !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(trustMark) ||
        decodeProtectedHeader(trustMark).typ !== 'trust-mark+jwt'
      )
        throw failure('EK_EID_FEDERATION');
      const target = this.endpoint(endpoint),
        body = new URLSearchParams({ trust_mark: trustMark }).toString();
      return await this.read(target, 'application/trust-mark-status-response+jwt', body, options);
    } catch (error) {
      throw transportFailure(error);
    }
  }
  stats() {
    return Object.freeze({ ...this.client.stats(), active: this.active });
  }
  close(options?: OperationOptions) {
    return this.client.close(this.options(options));
  }
}
