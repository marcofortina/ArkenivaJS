// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder, types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';
import { createHttpClient } from '@arkenivajs/http';
import type { ManagedHttpClient } from '@arkenivajs/http';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import { failure, fields, integer, list, url } from './validation.js';

export interface OidcProtocolEndpoints {
  readonly tokenEndpoint: string;
  readonly userInfoEndpoint: string;
  readonly jwksEndpoint?: string;
  readonly jwksFormat?: 'json' | 'signed';
}
/** Adapt only approved SDK protocol requests to the existing bounded native-TLS HTTP client. */
export class FederationProtocolHttp {
  private readonly client: ManagedHttpClient;
  private readonly approved: ReadonlySet<string>;
  private readonly inputMaximum: number;
  private readonly outputMaximum: number;
  constructor(settings: Settings, profileId: string) {
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId),
      registration = profile?.oidcRegistration;
    if (!profile || !registration?.approvedProtocolEndpoints) throw failure('EK_EID_PROFILE');
    this.approved = new Set(
      list(registration.approvedProtocolEndpoints).map((item) => new URL(url(item)).href),
    );
    this.inputMaximum = Math.min(
      profile.metadata.maxBytes,
      settings.policy.maxInputBytes ?? Infinity,
    );
    this.outputMaximum = Math.min(
      profile.metadata.maxBytes,
      settings.policy.maxOutputBytes ?? Infinity,
    );
    this.client = createHttpClient({
      allowedOrigins: [...new Set([...this.approved].map((endpoint) => new URL(endpoint).origin))],
      allowPrivateNetwork: settings.environment === 'test',
      timeoutMs: settings.policy.timeoutMs,
      connections: Math.min(64, settings.policy.maxConcurrent),
      maxResponseBytes: this.outputMaximum,
      retry: { attempts: 1 },
    });
  }
  fetch(call: FederationCall, input: OidcProtocolEndpoints) {
    const value = fields(input, [
        'tokenEndpoint',
        'userInfoEndpoint',
        'jwksEndpoint',
        'jwksFormat',
      ]),
      token = new URL(url(value.tokenEndpoint)).href,
      userInfo = new URL(url(value.userInfoEndpoint)).href,
      jwks = value.jwksEndpoint === undefined ? undefined : new URL(url(value.jwksEndpoint)).href;
    if (
      (value.jwksFormat !== undefined &&
        !['json', 'signed'].includes(value.jwksFormat as string)) ||
      (value.jwksFormat !== undefined && !jwks)
    )
      throw failure('EK_EID_FEDERATION');
    if (
      [token, userInfo, ...(jwks ? [jwks] : [])].some((endpoint) => !this.approved.has(endpoint)) ||
      jwks === userInfo
    )
      throw failure('EK_EID_FEDERATION');
    return async (target: string, init: unknown): Promise<Response> => {
      try {
        call.check();
        const endpoint = new URL(url(target)).href,
          request = fields(init, ['body', 'headers', 'method', 'redirect', 'signal', 'duplex']),
          role =
            endpoint === token && request.method === 'POST'
              ? 'token'
              : endpoint === userInfo && request.method === 'GET'
                ? 'userinfo'
                : endpoint === jwks && request.method === 'GET'
                  ? 'jwks'
                  : undefined;
        if (!role || request.redirect !== 'manual' || request.duplex !== undefined)
          throw failure('EK_EID_FEDERATION');
        const headerFields = fields(request.headers, [
            'accept',
            'authorization',
            'content-type',
            'user-agent',
          ]),
          headers = new Headers();
        for (const [name, value] of Object.entries(headerFields)) {
          if (
            typeof value !== 'string' ||
            Buffer.byteLength(value) > this.inputMaximum ||
            /[\r\n\0]/u.test(value) ||
            Buffer.from(value).toString() !== value
          )
            throw failure('EK_EID_FEDERATION');
          headers.set(name, value);
        }
        if (
          (role !== 'userinfo' && headers.has('authorization')) ||
          (role === 'userinfo' &&
            !/^Bearer [A-Za-z0-9\-._~+/]+=*$/u.test(headers.get('authorization') ?? ''))
        )
          throw failure('EK_EID_FEDERATION');
        let body: string | undefined;
        if (role === 'token') {
          if (
            !request.body ||
            typeof request.body !== 'object' ||
            types.isProxy(request.body) ||
            Object.getPrototypeOf(request.body) !== URLSearchParams.prototype
          )
            throw failure('EK_EID_FEDERATION');
          let entries = 0,
            bytes = 0;
          for (const [name, value] of URLSearchParams.prototype.entries.call(request.body)) {
            if (
              ++entries > 64 ||
              (bytes += Buffer.byteLength(name) + Buffer.byteLength(value)) > this.inputMaximum
            )
              throw failure('EK_EID_FEDERATION');
          }
          body = URLSearchParams.prototype.toString.call(request.body);
          if (headers.get('content-type')?.split(';')[0] !== 'application/x-www-form-urlencoded')
            throw failure('EK_EID_FEDERATION');
        } else if (request.body !== undefined && request.body !== null)
          throw failure('EK_EID_FEDERATION');
        if (
          Buffer.byteLength(endpoint) +
            Buffer.byteLength(JSON.stringify(headerFields)) +
            Buffer.byteLength(body ?? '') >
          this.inputMaximum
        )
          throw failure('EK_EID_FEDERATION');
        const selected = call.options(),
          signal =
            request.signal === undefined
              ? selected.signal
              : AbortSignal.any([selected.signal, captureAbortSignal(request.signal)]),
          response = await call.step((options) =>
            this.client.request(endpoint, {
              method: request.method as string,
              headers,
              ...(body === undefined ? {} : { body }),
              ...options,
              signal,
            }),
          );
        if (response.status >= 300 && response.status < 400) throw failure('EK_EID_FEDERATION');
        const content = response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase();
        if (
          !(role === 'userinfo'
            ? content === 'application/jwt'
            : role === 'jwks' && value.jwksFormat === 'signed'
              ? content === 'application/jwk-set+jwt'
              : content === 'application/json' ||
                (role === 'jwks' && content === 'application/jwk-set+json'))
        )
          throw failure('EK_EID_FEDERATION');
        const length = response.headers.get('content-length');
        if (length && (!/^\d+$/u.test(length) || Number(length) > this.outputMaximum))
          throw failure('EK_EID_FEDERATION');
        const bytes = await call.step(() => response.arrayBuffer());
        if (!bytes.byteLength || bytes.byteLength > this.outputMaximum)
          throw failure('EK_EID_FEDERATION');
        new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        call.check();
        return new Response(bytes, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      } catch (error) {
        if (
          error instanceof KitError &&
          ['EK_TIMEOUT', 'EK_ABORTED', 'EK_RESOURCE_CLOSED', 'EK_BACKEND_UNAVAILABLE'].includes(
            error.code,
          )
        )
          throw error;
        throw failure('EK_EID_FEDERATION');
      }
    };
  }
  stats() {
    return this.client.stats();
  }
  close(options?: OperationOptions) {
    const value = fields(options ?? {}, ['signal', 'timeoutMs']);
    return this.client.close({
      ...(value.signal === undefined ? {} : { signal: captureAbortSignal(value.signal) }),
      ...(value.timeoutMs === undefined ? {} : { timeoutMs: integer(value.timeoutMs) }),
    });
  }
}
