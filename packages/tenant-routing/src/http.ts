// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder } from 'node:util';
import type { Environment, RouteContext } from '@arkenivajs/core';
import { createFixedUpstreamPool } from '@arkenivajs/proxy/support';
import type {
  ApprovedUpstream,
  TenantHttpImplementation,
  TenantOperationDefinition,
} from './contracts.js';
import type { Settings } from './settings.js';
import { data } from './provider-support.js';
import { jsonSnapshot } from './json.js';
import { parseRegistryJson } from './registry.js';
import { routingFailure } from './errors.js';
type Pool = Awaited<ReturnType<typeof createFixedUpstreamPool>>;

const forbiddenProduction = [
  '0.0.0.0/8',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '100.100.100.200/32',
  '::/128',
  '::1/128',
  'fe80::/10',
  'fd00:ec2::254/128',
];
function text(input: unknown, max = 2048): string {
  if (
    typeof input !== 'string' ||
    !input.length ||
    input.length > max ||
    [...input].some((value) => value.charCodeAt(0) < 32 || value.charCodeAt(0) === 127)
  )
    throw routingFailure();
  return input;
}
function strings(input: unknown, max = 64, minimum = 1): readonly string[] {
  const value = jsonSnapshot(input, 65536);
  if (!Array.isArray(value) || value.length < minimum || value.length > max) throw routingFailure();
  const values = value.map((item) => text(item, 253));
  if (new Set(values).size !== values.length) throw routingFailure();
  return Object.freeze(values);
}
function instant(input: unknown): number {
  const value = text(input, 64);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value))
    throw routingFailure('EK_TROUTE_UPSTREAM');
  const at = Date.parse(value);
  if (
    !Number.isFinite(at) ||
    at <= Date.now() ||
    new Date(at).toISOString().slice(0, 19) !== value.slice(0, 19)
  )
    throw routingFailure('EK_TROUTE_UPSTREAM');
  return at;
}
function queryString(input: unknown): string {
  const values = data(input),
    parts: string[] = [];
  let bytes = 0;
  for (const [key, value] of Object.entries(values)) {
    if (key.length > 16384) throw routingFailure('EK_TROUTE_CONTRACT', true);
    for (const item of Array.isArray(value) ? value : [value]) {
      if (
        typeof item !== 'string' &&
        typeof item !== 'number' &&
        typeof item !== 'boolean' &&
        item !== null
      )
        throw routingFailure('EK_TROUTE_CONTRACT', true);
      const text = item === null ? '' : String(item);
      if (text.length > 16384) throw routingFailure('EK_TROUTE_CONTRACT', true);
      const pair = new URLSearchParams([[key, text]]).toString();
      bytes += Buffer.byteLength(pair) + 1;
      if (bytes > 16384) throw routingFailure('EK_TROUTE_CONTRACT', true);
      parts.push(pair);
    }
  }
  return parts.length ? '?' + parts.join('&') : '';
}
interface Target {
  readonly settings: ApprovedUpstream;
  readonly pool: Pool;
}

/** Fixed approved transports; no inbound credentials or request-selected origin enters this layer. */
export class HttpUpstreams {
  private readonly targets = new Map<string, Target>();
  private closed = false;
  private constructor(private readonly configuration: Settings) {}
  static async create(
    configuration: Settings,
    environment: Environment,
    signal: AbortSignal,
  ): Promise<HttpUpstreams> {
    const service = new HttpUpstreams(configuration);
    try {
      for (const raw of configuration.approvedUpstreams) {
        signal.throwIfAborted();
        const value = data(raw, [
          'key',
          'origin',
          'allowedHostnames',
          'allowedCidrs',
          'tlsCaFile',
          'connectionTimeoutMs',
          'allowRedirects',
          'forwardClientAuthorization',
          'serviceAuth',
        ]);
        const key = text(value.key, 128),
          origin = text(value.origin),
          hosts = strings(value.allowedHostnames),
          cidrs = strings(value.allowedCidrs);
        if (
          !/^[a-z][a-z0-9._-]*$/.test(key) ||
          service.targets.has(key) ||
          value.allowRedirects !== false ||
          (value.forwardClientAuthorization !== undefined &&
            value.forwardClientAuthorization !== false) ||
          !Number.isSafeInteger(value.connectionTimeoutMs) ||
          (value.connectionTimeoutMs as number) < 1 ||
          (value.connectionTimeoutMs as number) > 120000
        )
          throw routingFailure();
        const url = new URL(origin);
        if (environment === 'production' && url.protocol !== 'https:') throw routingFailure();
        let auth: ApprovedUpstream['serviceAuth'];
        if (value.serviceAuth !== undefined) {
          const credentials = data(value.serviceAuth, ['audience', 'scopes']);
          const audience = text(credentials.audience),
            scopes = strings(credentials.scopes, 64, 0).map((scope) => {
              if (/\s/.test(scope) || scope.length > 128) throw routingFailure();
              return scope;
            });
          if (url.protocol !== 'https:' || !configuration.credentialProvider)
            throw routingFailure();
          auth = Object.freeze({ audience, scopes: Object.freeze(scopes) });
        }
        const ca = value.tlsCaFile === undefined ? undefined : text(value.tlsCaFile, 4096);
        if (ca && url.protocol !== 'https:') throw routingFailure();
        const target: ApprovedUpstream = Object.freeze({
          key,
          origin,
          allowedHostnames: hosts,
          allowedCidrs: cidrs,
          connectionTimeoutMs: value.connectionTimeoutMs as number,
          allowRedirects: false,
          forwardClientAuthorization: false,
          ...(ca ? { tlsCaFile: ca } : {}),
          ...(auth ? { serviceAuth: auth } : {}),
        });
        const pool = await createFixedUpstreamPool({
          upstreamOrigin: origin,
          destinationPolicy: {
            kind: 'private-allowlisted',
            allowedHosts: hosts,
            allowedCidrs: cidrs,
          },
          connectionTimeoutMs: target.connectionTimeoutMs,
          ...(ca ? { upstreamCaFile: ca } : {}),
          ...(environment === 'test' ? {} : { deniedCidrs: forbiddenProduction }),
        });
        service.targets.set(key, { settings: target, pool });
        signal.throwIfAborted();
      }
      return service;
    } catch {
      await service.close();
      throw routingFailure('EK_TROUTE_REGISTRY');
    }
  }
  validate(implementation: TenantHttpImplementation): void {
    if (
      !this.targets.has(implementation.upstreamKey) ||
      (implementation.requestTransformerKey !== undefined &&
        !this.configuration.requestTransformers.has(implementation.requestTransformerKey)) ||
      ((implementation.responseTransformerKey ?? implementation.transformerKey) !== undefined &&
        !this.configuration.responseTransformers.has(
          (implementation.responseTransformerKey ?? implementation.transformerKey)!,
        ))
    )
      throw routingFailure('EK_TROUTE_REGISTRY');
  }
  async execute(
    implementation: TenantHttpImplementation,
    operation: TenantOperationDefinition,
    context: RouteContext,
  ): Promise<unknown> {
    if (this.closed) throw routingFailure('EK_RESOURCE_CLOSED');
    context.signal.throwIfAborted();
    const target = this.targets.get(implementation.upstreamKey);
    if (!target) throw routingFailure('EK_TROUTE_UPSTREAM');
    let payload: unknown = implementation.method === 'GET' ? context.query : context.body;
    const request =
      implementation.requestTransformerKey === undefined
        ? undefined
        : this.configuration.requestTransformers.get(implementation.requestTransformerKey);
    if (request) payload = await request(payload, context);
    context.signal.throwIfAborted();
    let body: string | undefined,
      path = implementation.upstreamPath;
    try {
      if (implementation.method === 'GET')
        path += queryString(
          jsonSnapshot(payload === undefined ? {} : payload, operation.maxBodyBytes),
        );
      else {
        path += queryString(context.query);
        if (payload !== undefined)
          body = JSON.stringify(jsonSnapshot(payload, operation.maxBodyBytes));
      }
    } catch {
      throw routingFailure('EK_TROUTE_CONTRACT', true);
    }
    const headers: Record<string, string> = {
      accept: 'application/json',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    };
    let expires: number | undefined;
    if (target.settings.serviceAuth) {
      const policy = target.settings.serviceAuth;
      const returned = await this.configuration.credentialProvider!.get(
        {
          upstreamKey: target.settings.key,
          audience: policy.audience,
          scopes: policy.scopes,
          tenant: context.auth!,
          operationId: operation.id,
        },
        { signal: context.signal, timeoutMs: operation.timeoutMs },
      );
      context.signal.throwIfAborted();
      try {
        const credential = data(returned, [
          'authorizationHeader',
          'expiresAt',
          'audience',
          'scopes',
        ]);
        const granted = strings(credential.scopes, 64, 0),
          authorization = text(credential.authorizationHeader, 8192);
        if (
          !/^(?:Bearer|Basic) [\x21-\x7e]+$/.test(authorization) ||
          credential.audience !== policy.audience ||
          granted.length !== policy.scopes.length ||
          granted.some((scope) => !policy.scopes.includes(scope))
        )
          throw routingFailure('EK_TROUTE_UPSTREAM');
        expires = instant(credential.expiresAt);
        headers.authorization = authorization;
      } catch {
        throw routingFailure('EK_TROUTE_UPSTREAM');
      }
    }
    context.signal.throwIfAborted();
    const expiry = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (expires !== undefined && expires - Date.now() <= operation.timeoutMs) {
      if (expires <= Date.now()) throw routingFailure('EK_TROUTE_UPSTREAM');
      timer = setTimeout(() => expiry.abort(), Math.max(1, Math.floor(expires - Date.now())));
    }
    try {
      const response = await target.pool.request({
        method: implementation.method,
        path,
        headers,
        ...(body === undefined ? {} : { body }),
        signal: AbortSignal.any([context.signal, expiry.signal]),
        headersTimeout: operation.timeoutMs,
        bodyTimeout: operation.timeoutMs,
        idempotent: false,
      });
      // Rejected headers still require destroying an unread native stream. Its
      // cancellation error is owned here; async iteration retains its own errors.
      response.body.on('error', () => {});
      try {
        context.signal.throwIfAborted();
        if (response.statusCode < 200 || response.statusCode >= 300)
          throw routingFailure('EK_TROUTE_UPSTREAM');
        const type = response.headers['content-type'];
        if (
          typeof type !== 'string' ||
          !/^application\/json(?:\s*;\s*charset\s*=\s*"?utf-8"?)?\s*$/i.test(type)
        )
          throw routingFailure('EK_TROUTE_CONTRACT', true);
        const declared = response.headers['content-length'];
        if (
          declared !== undefined &&
          (typeof declared !== 'string' ||
            !/^\d+$/.test(declared) ||
            BigInt(declared) > BigInt(operation.maxResponseBytes))
        )
          throw routingFailure('EK_TROUTE_CONTRACT', true);
        const parts: Buffer[] = [];
        let bytes = 0;
        for await (const chunk of response.body) {
          context.signal.throwIfAborted();
          const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          bytes += value.length;
          if (bytes > operation.maxResponseBytes) throw routingFailure('EK_TROUTE_CONTRACT', true);
          parts.push(value);
        }
        let result: unknown;
        try {
          result = parseRegistryJson(
            new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
              Buffer.concat(parts, bytes),
            ),
            operation.maxResponseBytes,
          );
        } catch {
          throw routingFailure('EK_TROUTE_CONTRACT', true);
        }
        const responseKey = implementation.responseTransformerKey ?? implementation.transformerKey;
        const transform =
          responseKey === undefined
            ? undefined
            : this.configuration.responseTransformers.get(responseKey);
        try {
          result = jsonSnapshot(result, operation.maxResponseBytes);
        } catch {
          throw routingFailure('EK_TROUTE_CONTRACT', true);
        }
        if (transform) result = await transform(result, context);
        context.signal.throwIfAborted();
        try {
          return jsonSnapshot(result, operation.maxResponseBytes);
        } catch {
          throw routingFailure('EK_TROUTE_CONTRACT', true);
        }
      } finally {
        response.body.destroy();
      }
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  async close(): Promise<void> {
    this.closed = true;
    await Promise.allSettled([...this.targets.values()].map((target) => target.pool.destroy()));
    this.targets.clear();
  }
}
