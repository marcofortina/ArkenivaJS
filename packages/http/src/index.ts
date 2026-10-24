import { lookup as resolveHost } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import type { LookupFunction } from 'node:net';
import { performance } from 'node:perf_hooks';
import { setTimeout as delay } from 'node:timers/promises';
import { Agent, fetch as send } from 'undici';
import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type {
  OutboundHttpClient,
  OperationOptions,
  Plugin,
  Telemetry,
  UsageMeter,
  MeterSession,
} from '@arkenivajs/core';
import { copyData, within, instrumentOperation } from '@arkenivajs/core/support';

export type { OutboundHttpClient } from '@arkenivajs/core';
/** Default deadline covers connection, headers and bounded response consumption. */
export const DEFAULT_HTTP_TIMEOUT_MS = 10_000;
/** Safe operation metadata excludes URLs, headers, credentials and payloads. */
export interface HttpObservation {
  readonly method: string;
  readonly durationMs: number;
  readonly outcome: 'ok' | 'error';
  readonly status?: number;
  readonly responseBytes?: number;
}
/** Explicit destination policy; private network access is an isolated-test opt-in. */
export interface HttpClientOptions {
  readonly allowedOrigins: readonly string[];
  readonly allowPrivateNetwork?: boolean;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly connections?: number;
  readonly retry?: { readonly attempts: number; readonly delayMs?: number };
  readonly resolve?: (hostname: string) => Promise<readonly { address: string; family: 4 | 6 }[]>;
  readonly traceHeaders?: () => Readonly<{ traceparent?: string; tracestate?: string }>;
  readonly serviceToken?: (origin: string, signal: AbortSignal) => Promise<string>;
  readonly onObservation?: (event: HttpObservation) => void;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
}
/** A standalone client owns its connection agent and must be closed. */
export interface ManagedHttpClient extends OutboundHttpClient {
  close(options?: OperationOptions): Promise<void>;
  stats(): Readonly<{
    completed: number;
    failed: number;
    active: number;
    observerFailures: number;
  }>;
}

const privateNetworks = new BlockList();
for (const [network, bits] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 3],
] as const)
  privateNetworks.addSubnet(network, bits, 'ipv4');
for (const [network, bits] of [
  ['::', 96],
  ['::ffff:0:0', 96],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
  ['2001:db8::', 32],
  ['2001::', 23],
  ['2002::', 16],
] as const)
  privateNetworks.addSubnet(network, bits, 'ipv6');
const globalIpv6 = new BlockList();
globalIpv6.addSubnet('2000::', 3, 'ipv6');
const invalid = (message: string) => new KitError({ code: 'EK_CONFIG_INVALID', message });
const positive = (value: number) => Number.isSafeInteger(value) && value > 0;
const publicAddress = (address: string): boolean => {
  const family = isIP(address);
  return (
    family !== 0 &&
    (family !== 6 || globalIpv6.check(address, 'ipv6')) &&
    !privateNetworks.check(address, family === 4 ? 'ipv4' : 'ipv6')
  );
};

/** EK-HTTP-002: bounded Undici client with connection-time DNS and origin enforcement. */
export function createHttpClient(options: HttpClientOptions): ManagedHttpClient {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
  const maxBytes = options?.maxResponseBytes ?? 8_388_608;
  const connections = options?.connections ?? 10;
  const attempts = options?.retry?.attempts ?? 1;
  const retryDelay = options?.retry?.delayMs ?? 100;
  if (
    !options ||
    !Array.isArray(options.allowedOrigins) ||
    !positive(timeoutMs) ||
    !positive(maxBytes) ||
    maxBytes > 67_108_864 ||
    !positive(connections) ||
    connections > 64 ||
    !positive(attempts) ||
    attempts > 3 ||
    !Number.isSafeInteger(retryDelay) ||
    retryDelay < 0 ||
    retryDelay > 1000 ||
    (options.allowPrivateNetwork !== undefined && typeof options.allowPrivateNetwork !== 'boolean')
  )
    throw invalid('Invalid HTTP client options');
  for (const callback of [
    options.resolve,
    options.traceHeaders,
    options.serviceToken,
    options.onObservation,
  ])
    if (callback !== undefined && typeof callback !== 'function')
      throw invalid('Invalid HTTP callback');
  options = Object.freeze({
    ...options,
    allowedOrigins: Object.freeze([...options.allowedOrigins]),
  });
  const allowed = new Set(
    options.allowedOrigins.map((origin) => {
      try {
        const url = new URL(origin);
        if (
          !['https:', 'http:'].includes(url.protocol) ||
          url.username ||
          url.password ||
          url.pathname !== '/' ||
          url.search ||
          url.hash ||
          (url.protocol === 'http:' && !options.allowPrivateNetwork)
        )
          throw invalid('Invalid allowed HTTP origin');
        return url.origin;
      } catch (cause) {
        throw new KitError({
          code: 'EK_CONFIG_INVALID',
          message: 'Invalid allowed HTTP origin',
          cause,
        });
      }
    }),
  );
  const lookup: LookupFunction = (hostname, lookupOptions, callback) => {
    const resolution = Promise.resolve().then(() =>
      options.resolve
        ? options.resolve(hostname)
        : resolveHost(hostname, { all: true, verbatim: true }).then((rows) =>
            rows.map((row) => ({ address: row.address, family: row.family as 4 | 6 })),
          ),
    );
    void resolution
      .then((addresses) => {
        if (
          !Array.isArray(addresses) ||
          addresses.length === 0 ||
          addresses.some(
            (row) =>
              !row ||
              ![4, 6].includes(row.family) ||
              isIP(row.address) !== row.family ||
              (!options.allowPrivateNetwork && !publicAddress(row.address)),
          )
        ) {
          callback(invalid('HTTP destination resolved to a disallowed address'), '');
          return;
        }
        const selected = lookupOptions.family
          ? addresses.filter((row) => row.family === lookupOptions.family)
          : addresses;
        if (selected.length === 0) {
          callback(invalid('HTTP destination address family is unavailable'), '');
          return;
        }
        if (lookupOptions.all) callback(null, [...selected]);
        else callback(null, selected[0]!.address, selected[0]!.family);
      })
      .catch((cause: unknown) =>
        callback(
          new KitError({ code: 'EK_HTTP_UPSTREAM', message: 'HTTP name resolution failed', cause }),
          '',
        ),
      );
  };
  const agent = new Agent({
    connections,
    connect: { lookup, rejectUnauthorized: true, minVersion: 'TLSv1.2' },
  });
  const active = new Set<AbortController>();
  const counters = { completed: 0, failed: 0, observerFailures: 0 };
  let closed = false,
    closing: Promise<void> | undefined;

  const perform: OutboundHttpClient['request'] = async (input, init) => {
    if (closed)
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'HTTP client is closed' });
    const began = performance.now();
    let method = 'GET',
      status: number | undefined,
      responseBytes: number | undefined;
    const controller = new AbortController();
    active.add(controller);
    const abort = () => controller.abort(init?.signal?.reason);
    init?.signal?.addEventListener('abort', abort, { once: true });
    let outcome: 'ok' | 'error' = 'error';
    let meterSession: MeterSession | undefined;
    try {
      meterSession = options.meter?.current();
    } catch {
      counters.observerFailures++;
    }
    const markGap = (reason: 'driver_bytes_unavailable' | 'downstream_unobserved') => {
      if (!meterSession) return;
      try {
        const scoped = options.meter as UsageMeter & {
          markMissing?: (
            session: MeterSession,
            reason: 'driver_bytes_unavailable' | 'downstream_unobserved',
          ) => void;
        };
        if (typeof scoped.markMissing !== 'function') counters.observerFailures++;
        else scoped.markMissing(meterSession, reason);
      } catch {
        counters.observerFailures++;
      }
    };
    try {
      if (!init || typeof init !== 'object') throw invalid('HTTP request options are required');
      let url: URL;
      try {
        url = new URL(input);
      } catch {
        throw invalid('Invalid HTTP destination URL');
      }
      const hostname = url.hostname.replace(/^\[|\]$/g, '');
      if (
        !allowed.has(url.origin) ||
        url.username ||
        url.password ||
        url.hash ||
        (!options.allowPrivateNetwork && isIP(hostname) && !publicAddress(hostname))
      )
        throw invalid('HTTP destination is not allowed');
      method = (init.method ?? 'GET').toUpperCase();
      if (
        !['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method) ||
        (init.redirect !== undefined && init.redirect !== 'manual')
      )
        throw invalid('Unsupported HTTP request policy');
      const headers = new Headers(init.headers);
      for (const name of [
        'x-tenant-id',
        'tenant-id',
        'tenant_id',
        'baggage',
        'host',
        'connection',
        'content-length',
      ])
        headers.delete(name);
      const validParent = (value: string) =>
        /^00-[0-9a-f]{32}-[0-9a-f]{16}-0[01]$/.test(value) &&
        !/^00-0{32}-|^00-[0-9a-f]{32}-0{16}-/.test(value);
      const traceparent = headers.get('traceparent');
      if (traceparent && !validParent(traceparent)) throw invalid('Invalid outbound trace context');
      try {
        const correlation = options.traceHeaders?.();
        if (correlation?.traceparent && !validParent(correlation.traceparent))
          throw invalid('Invalid diagnostic trace context');
        const carrier = new Headers();
        if (correlation?.traceparent) carrier.set('traceparent', correlation.traceparent);
        if (correlation?.tracestate) carrier.set('tracestate', correlation.tracestate);
        for (const [name, value] of carrier) headers.set(name, value);
      } catch {
        counters.observerFailures++;
        markGap('downstream_unobserved');
      }
      if (init.idempotencyKey !== undefined) {
        if (!/^[a-zA-Z0-9_.:-]{1,200}$/.test(init.idempotencyKey))
          throw invalid('Invalid idempotency key');
        headers.set('idempotency-key', init.idempotencyKey);
      }
      const retryableMethod = ['GET', 'HEAD', 'OPTIONS', 'PUT', 'DELETE'].includes(method);
      const count = retryableMethod ? attempts : 1;
      if (
        count > 1 &&
        init.body != null &&
        typeof init.body !== 'string' &&
        !(init.body instanceof Uint8Array) &&
        !(init.body instanceof ArrayBuffer)
      )
        throw invalid('Automatic retry requires a replayable request body');
      const result = await within(
        async () => {
          if (options.serviceToken) {
            const token = await options.serviceToken(url.origin, controller.signal);
            if (typeof token !== 'string' || token.length === 0 || /[\r\n]/.test(token))
              throw invalid('Invalid outbound service token');
            headers.set('authorization', `Bearer ${token}`);
          }
          for (let attempt = 0; ; attempt++) {
            let response;
            try {
              const { timeoutMs: _timeout, idempotencyKey: _key, ...nativeInit } = init;
              void [_timeout, _key];
              response = await send(url, {
                ...nativeInit,
                method,
                headers: [...headers],
                signal: controller.signal,
                redirect: 'manual',
                dispatcher: agent,
              } as Parameters<typeof send>[1]);
            } catch (cause) {
              if (attempt + 1 >= count || controller.signal.aborted) throw cause;
              await delay(retryDelay, undefined, { signal: controller.signal });
              continue;
            }
            if ([502, 503, 504].includes(response.status) && attempt + 1 < count) {
              await response.body?.cancel();
              await delay(retryDelay, undefined, { signal: controller.signal });
              continue;
            }
            status = response.status;
            const chunks: Uint8Array[] = [];
            responseBytes = 0;
            const reader = response.body?.getReader();
            if (reader) {
              try {
                for (;;) {
                  const part = await reader.read();
                  if (part.done) break;
                  responseBytes += part.value.byteLength;
                  if (responseBytes > maxBytes) {
                    await reader.cancel();
                    throw new KitError({
                      code: 'EK_HTTP_UPSTREAM',
                      message: 'Upstream response exceeds the configured limit',
                      details: { limitExceeded: true },
                    });
                  }
                  chunks.push(part.value);
                }
              } finally {
                reader.releaseLock();
              }
            }
            const body = Buffer.concat(chunks);
            const value = new Response(
              method === 'HEAD' || [204, 205, 304].includes(status) ? null : body,
              { status, statusText: response.statusText, headers: [...response.headers] },
            );
            Object.defineProperty(value, 'url', { value: url.href });
            return value;
          }
        },
        { timeoutMs: init.timeoutMs ?? timeoutMs, ...(init.signal ? { signal: init.signal } : {}) },
      );
      counters.completed++;
      outcome = 'ok';
      return result;
    } catch (cause) {
      counters.failed++;
      if (cause instanceof KitError && cause.code === 'EK_TIMEOUT')
        throw new KitError({
          code: 'EK_TIMEOUT',
          message: 'Upstream HTTP deadline exceeded',
          details: { upstream: true },
          cause,
        });
      if (cause instanceof KitError) throw cause;
      if (controller.signal.aborted)
        throw new KitError({ code: 'EK_ABORTED', message: 'HTTP request aborted', cause });
      throw new KitError({ code: 'EK_HTTP_UPSTREAM', message: 'HTTP request failed', cause });
    } finally {
      controller.abort();
      init?.signal?.removeEventListener('abort', abort);
      active.delete(controller);
      if (meterSession) {
        try {
          meterSession.recordOperation('http.client.requests');
          meterSession.recordUsage('http.client.elapsed', {
            unit: 'milliseconds',
            source: 'observed',
            value: performance.now() - began,
          });
          if (responseBytes !== undefined)
            meterSession.recordUsage('http.client.response.bytes', {
              unit: 'bytes',
              source: 'observed',
              value: responseBytes,
            });
          else markGap('driver_bytes_unavailable');
        } catch {
          counters.observerFailures++;
        }
      }
      if (options.telemetry) {
        try {
          options.telemetry.recordHistogram(
            'http.client.request.duration',
            (performance.now() - began) / 1000,
            {
              method,
              ...(status === undefined ? {} : { status_code: status }),
            },
          );
          if (responseBytes !== undefined)
            options.telemetry.recordHistogram('arkenivajs.http.body.bytes', responseBytes, {
              direction: 'client.response',
            });
        } catch {
          counters.observerFailures++;
        }
      }
      try {
        options.onObservation?.(
          Object.freeze({
            method,
            durationMs: performance.now() - began,
            outcome,
            ...(status === undefined ? {} : { status }),
            ...(responseBytes === undefined ? {} : { responseBytes }),
          }),
        );
      } catch {
        counters.observerFailures++;
      }
    }
  };
  const request: OutboundHttpClient['request'] = (input, init) =>
    instrumentOperation(
      options.telemetry,
      'http.client.request',
      {},
      () => perform(input, init),
      () => {
        counters.observerFailures++;
      },
    );
  return Object.freeze({
    request,
    get: (url: string, operation: OperationOptions = {}) =>
      request(url, { ...operation, method: 'GET' }),
    post: (
      url: string,
      body: unknown,
      operation: OperationOptions & { idempotencyKey?: string } = {},
    ) => {
      try {
        return request(url, {
          ...operation,
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(copyData(body)),
        });
      } catch (cause) {
        return Promise.reject(cause);
      }
    },
    stats: () => Object.freeze({ ...counters, active: active.size }),
    close(operation: OperationOptions = {}): Promise<void> {
      if (closing) return closing;
      closed = true;
      for (const controller of active) controller.abort();
      closing = within(() => agent.close(), operation).catch(async (error: unknown) => {
        await agent.destroy();
        throw error;
      });
      return closing;
    },
  });
}

/** Plugin composition additionally declares explicit capability dependencies. */
export interface HttpPluginOptions extends HttpClientOptions {
  readonly dependencies?: readonly string[];
}
/** Explicit dependency access wires telemetry without importing a concrete SDK. */
export function httpPlugin(options: HttpPluginOptions): Plugin {
  return {
    id: 'http',
    version: '0.1.0',
    capabilities: new Set(['http']),
    dependencies: options.dependencies ?? [],
    init(context) {
      const telemetry = context.options.telemetry
        ? context.require<Telemetry>(COMPONENTS.telemetry)
        : options.telemetry;
      const meter = context.options.metering?.enabled
        ? context.require<UsageMeter>(COMPONENTS.meter)
        : options.meter;
      const contextual = telemetry as
        | (Telemetry & {
            traceHeaders?: () => Readonly<{ traceparent?: string; tracestate?: string }>;
          })
        | undefined;
      context.provide(
        COMPONENTS.http,
        createHttpClient({
          ...options,
          ...(telemetry ? { telemetry } : {}),
          ...(meter ? { meter } : {}),
          ...(options.traceHeaders
            ? {}
            : typeof contextual?.traceHeaders === 'function'
              ? { traceHeaders: () => contextual.traceHeaders!() }
              : {}),
        }),
      );
    },
    async close(context) {
      await context
        .require<ManagedHttpClient>(COMPONENTS.http)
        .close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
    },
  };
}
