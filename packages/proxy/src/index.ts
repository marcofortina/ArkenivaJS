// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export type * from './contracts.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { open, constants } from 'node:fs/promises';
import { createSecureContext } from 'node:tls';
import { Pool } from 'undici';
import type { Dispatcher } from 'undici';
import nativeProxy from '@fastify/http-proxy';
import type { FastifyInstance } from 'fastify';
import { APPLICATION_SIGNAL, COMPONENTS } from '@arkenivajs/core';
import type { Plugin, AuthService, Logger, Telemetry } from '@arkenivajs/core';
import {
  SUPPORT_PLUGINS,
  PREPARE_PLUGIN,
  DRAIN_PLUGIN,
  within,
  instrumentOperation,
} from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { ManagedApiServer } from '@arkenivajs/api';
import type { ProxyPluginSettings, ProxyService } from './contracts.js';
import { capture, failure, text } from './policy.js';
import { guardedLookup } from './network.js';
import { Scope, translated, status } from './runtime.js';
import { contentHeaders, validateTarget } from './headers.js';
import { remoteTrace, injectTrace } from './trace.js';
import { MTLS_CAPABILITY } from '@arkenivajs/security-mtls';
import type { MtlsService } from '@arkenivajs/security-mtls';
import { mtlsConnector } from './mtls.js';

export const PROXY_CAPABILITY: unique symbol = Symbol('arkenivajs.proxy');
const OBSERVERS = Symbol('proxy.observers');
interface Observers {
  readonly auth?: AuthService;
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly mtls?: MtlsService;
}
const observers: SupportPluginFactory = (options) => {
  const auth = options.plugins?.find((p) => p.capabilities.has('auth')),
    logger = options.plugins?.find((p) => p.capabilities.has('logger')),
    telemetry = options.plugins?.find((p) => p.capabilities.has('telemetry')),
    mtls = options.plugins?.find((p) => p.capabilities.has('mtls'));
  return {
    id: 'proxy-observers',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [
      ...new Set(
        [auth?.id, logger?.id, telemetry?.id, mtls?.id].filter((v): v is string => v !== undefined),
      ),
    ],
    init(context) {
      context.provide<Observers>(OBSERVERS, {
        ...(auth ? { auth: context.require<AuthService>(COMPONENTS.auth) } : {}),
        ...(logger ? { logger: context.require<Logger>(COMPONENTS.logger) } : {}),
        ...(telemetry ? { telemetry: context.require<Telemetry>(COMPONENTS.telemetry) } : {}),
        ...(mtls ? { mtls: context.require<MtlsService>(MTLS_CAPABILITY) } : {}),
      });
    },
    close() {},
  };
};
const safe = (work: () => unknown) => {
  try {
    void Promise.resolve(work()).catch(() => undefined);
  } catch {
    /* Observation cannot alter proxy authorization or replay a request. */
  }
};
async function trustFile(path: string): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 1048576) throw failure();
    const ca = await handle.readFile();
    createSecureContext({ ca, minVersion: 'TLSv1.2' });
    return ca;
  } finally {
    await handle.close();
  }
}
/** Register bounded routes before listener activation; monitoring is the only public runtime capability. */
export function proxyPlugin(input: ProxyPluginSettings): Plugin {
  const settings = capture(input),
    instances = new WeakMap<object, { close(): Promise<void> }>(),
    readiness = new WeakMap<object, () => boolean>();
  const plugin: ComposablePlugin = {
    id: 'proxy',
    version: '0.1.0',
    capabilities: new Set(['proxy']),
    dependencies: ['api', 'proxy-observers'],
    [SUPPORT_PLUGINS]: [observers],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      const observed = context.require<Observers>(OBSERVERS),
        api = context.require<ManagedApiServer>(COMPONENTS.api),
        server = api.native();
      if (settings.routes.some((route) => route.auth.required) && !observed.auth) throw failure();
      const ready = readiness.get(context.options);
      if (!ready) throw failure();
      const owner = context.require<AbortSignal>(APPLICATION_SIGNAL),
        storage = new AsyncLocalStorage<Scope>(),
        scopes = new Set<Scope>(),
        requests = new WeakMap<object, Scope>(),
        pools: Pool[] = [];
      const counters = {
        activeRequests: 0,
        forwardedRequests: 0,
        rejectedRequests: 0,
        observedRequestBytes: 0,
        observedResponseBytes: 0,
      };
      let closed = false,
        closing: Promise<void> | undefined;
      const close = () =>
        (closing ??= (async () => {
          closed = true;
          const deadline = Math.max(...settings.routes.map((route) => route.timeoutMs));
          try {
            await within(() => Promise.all([...scopes].map((scope) => scope.completion)), {
              timeoutMs: deadline,
            });
          } catch {
            for (const scope of scopes) {
              scope.fail('EK_RESOURCE_CLOSED');
              scope.respond();
              scope.finish();
            }
          }
          await Promise.allSettled(pools.map((pool) => pool.destroy()));
          storage.disable();
        })());
      instances.set(context, { close });
      try {
        const ownership = Symbol('proxy.route.owner');
        server.addHook('onRoute', (options) => {
          const url = options.url;
          for (const route of settings.routes) {
            if (
              (route.prefix === '/' ||
                url === route.prefix ||
                url.startsWith(route.prefix + '/')) &&
              (options.config as Record<symbol, unknown> | undefined)?.[ownership] !== route.routeId
            )
              throw failure();
          }
        });
        for (const route of settings.routes) {
          if (
            route.methods.some((method) =>
              [route.prefix, route.prefix + '/', route.prefix + '/*'].some((url) =>
                server.hasRoute({ method, url }),
              ),
            )
          )
            throw failure();
          let ca: Buffer | undefined;
          try {
            if (route.upstreamCaFile) ca = await trustFile(route.upstreamCaFile);
          } catch {
            throw failure();
          }
          if (
            route.identityDelegation === 'validated-service-credential' &&
            !route.upstreamOrigin.startsWith('https:')
          )
            throw failure();
          if (route.upstreamTlsProfile && !observed.mtls) throw failure();
          const pool = new Pool(route.upstreamOrigin, {
            allowH2: false,
            connections: 16,
            pipelining: 1,
            headersTimeout: route.timeoutMs,
            bodyTimeout: route.timeoutMs,
            maxHeaderSize: 16384,
            connect: route.upstreamTlsProfile
              ? mtlsConnector(route, observed.mtls!)
              : {
                  lookup: guardedLookup(route),
                  rejectUnauthorized: true,
                  minVersion: 'TLSv1.2',
                  timeout: route.timeoutMs,
                  ...(ca ? { ca } : {}),
                },
          });
          pools.push(pool);
          const dispatcher = {
            destroy() {
              void pool.destroy().catch(() => undefined);
            },
            request(
              options: Dispatcher.RequestOptions,
              callback: (error: Error | null, data: Dispatcher.ResponseData) => void,
            ) {
              const scope = storage.getStore();
              if (!scope) throw failure('EK_PROXY_POLICY');
              scope.check();
              scope.forwarded = true;
              counters.forwardedRequests++;
              let settle!: () => void;
              scope.watch(
                new Promise<void>((resolve) => {
                  settle = resolve;
                }),
              );
              try {
                pool.request(
                  { ...options, origin: route.upstreamOrigin, signal: scope.controller.signal },
                  (error, data) => {
                    if (error) {
                      settle();
                      callback(translated(error), data);
                      return;
                    }
                    const finished = () => {
                      settle();
                      scope.upstreamEnded();
                    };
                    data.body.once('end', finished);
                    data.body.once('close', finished);
                    scope.stream(data.body);
                    callback(null, data);
                  },
                );
              } catch (error) {
                settle();
                throw translated(error);
              }
            },
          };
          server.register(
            async (child: FastifyInstance) => {
              child.setErrorHandler((error, request, reply) => {
                const scope = requests.get(request);
                if (scope) {
                  scope.fail(translated(error).code);
                  scope.respond();
                } else {
                  const fixed = translated(error);
                  void reply
                    .code(status(fixed.code))
                    .send({ error: { code: fixed.code, message: fixed.message } });
                }
              });
              child.addHook('onRequest', async (request, reply) => {
                if (closed || owner.aborted || !ready()) throw failure('EK_RESOURCE_CLOSED');
                if (scopes.size >= 64) throw failure('EK_BACKEND_UNAVAILABLE');
                const scope = new Scope(
                  request,
                  reply,
                  route,
                  () => {
                    scopes.delete(scope);
                    counters.activeRequests = scopes.size;
                    if (scope.error) counters.rejectedRequests++;
                    const labels = {
                      route: route.prefix + '/*',
                      'peer.service': route.routeId,
                      'proxy.outcome': scope.error ? 'error' : 'ok',
                      status_code: reply.statusCode,
                    };
                    safe(() => observed.telemetry?.addCounter('proxy.requests', 1, labels));
                    safe(() =>
                      observed.telemetry?.recordHistogram(
                        'proxy.request.duration.ms',
                        performance.now() - scope.started,
                        labels,
                      ),
                    );
                    safe(() =>
                      observed.telemetry?.recordHistogram(
                        'proxy.request.bytes',
                        scope.requestBytes,
                        { route: route.prefix + '/*', 'peer.service': route.routeId },
                      ),
                    );
                    safe(() =>
                      observed.telemetry?.recordHistogram(
                        'proxy.response.bytes',
                        scope.responseBytes,
                        { route: route.prefix + '/*', 'peer.service': route.routeId },
                      ),
                    );
                    safe(() => observed.telemetry?.setGauge('proxy.requests.active', scopes.size));
                    safe(() =>
                      observed.logger?.debug('Proxy request completed', {
                        route: route.routeId,
                        outcome: scope.error ? 'error' : 'ok',
                        status: reply.statusCode,
                      }),
                    );
                  },
                  (side, bytes) => {
                    if (side === 'request') counters.observedRequestBytes += bytes;
                    else counters.observedResponseBytes += bytes;
                  },
                );
                scopes.add(scope);
                requests.set(request, scope);
                counters.activeRequests = scopes.size;
                safe(() => observed.telemetry?.setGauge('proxy.requests.active', scopes.size));
                validateTarget(request.raw.url ?? '');
                const length = request.headers['content-length'];
                if (
                  length !== undefined &&
                  (!/^\d+$/.test(length) || Number(length) > route.maxRequestBytes)
                )
                  throw scope.fail('EK_PROXY_BODY_LIMIT');
                if (
                  ['GET', 'HEAD'].includes(request.method) &&
                  ((length !== undefined && length !== '0') || request.headers['transfer-encoding'])
                )
                  throw scope.fail('EK_PROXY_POLICY');
                if (route.auth.required)
                  await scope.run(async () => {
                    const identity = await observed.auth!.verifyBearer(
                      request.headers.authorization,
                      scope.options(),
                    );
                    for (const claim of route.auth.required ? (route.auth.scopes ?? []) : [])
                      observed.auth!.requireScope(identity, claim);
                    observed.auth!.tenantFrom(identity);
                  });
                if (route.identityDelegation === 'validated-service-credential')
                  await scope.run(async () => {
                    let value: string;
                    try {
                      value = text(
                        await settings.resolveSecret!(
                          route.serviceCredentialSecretRef!,
                          scope.options(),
                        ),
                        8192,
                      );
                    } catch {
                      throw failure('EK_PROXY_POLICY');
                    }
                    if (!/^[A-Za-z][A-Za-z0-9_-]* [A-Za-z0-9._~+/-]+=*$/.test(value))
                      throw failure('EK_PROXY_POLICY');
                    scope.credential = value;
                  });
              });
              child.addHook('preParsing', (request, reply, payload, done) => {
                const scope = requests.get(request);
                if (!scope || ['GET', 'HEAD'].includes(request.method)) {
                  done(null, payload);
                  return;
                }
                const limiter = scope.limiter('request');
                const failed = () => {
                  payload.unpipe(limiter);
                  payload.pause();
                  if (request.raw.httpVersionMajor === 1) reply.header('connection', 'close');
                  scope.respond();
                };
                limiter.once('error', failed);
                payload.once('error', () => {
                  scope.fail('EK_ABORTED');
                  scope.respond();
                });
                payload.pipe(limiter);
                done(null, limiter);
              });
              child.addHook('onResponse', async (request) => {
                requests.get(request)?.finish();
              });
              child.register(nativeProxy, {
                upstream: route.upstreamOrigin,
                prefix: route.prefix,
                rewritePrefix: route.rewritePrefix ?? '',
                httpMethods: [...route.methods],
                websocket: false,
                disableRequestLogging: true,
                destroyAgent: true,
                disableCache: true,
                retryMethods: [],
                config: { [ownership]: route.routeId },
                // The official backend invokes the documented callback form of the requestable port.
                undici: dispatcher as unknown as NonNullable<
                  nativeProxy.FastifyHttpProxyOptions['undici']
                >,
                async handler(request, reply, destination, options) {
                  const scope = requests.get(request)!;
                  try {
                    await remoteTrace(observed.telemetry, request.headers, () =>
                      instrumentOperation(
                        observed.telemetry,
                        'proxy.request',
                        { route: route.prefix + '/*', 'peer.service': route.routeId },
                        () =>
                          instrumentOperation(
                            observed.telemetry,
                            'proxy.upstream',
                            { route: route.prefix + '/*', 'peer.service': route.routeId },
                            () =>
                              storage.run(scope, async () => {
                                scope.check();
                                reply.from(destination, options);
                                await scope.upstreamCompletion;
                                if (scope.error) throw scope.error;
                              }),
                            () => undefined,
                          ),
                        () => undefined,
                      ),
                    );
                  } catch (error) {
                    scope.fail(translated(error).code);
                    scope.respond();
                  }
                  return reply;
                },
                replyOptions: {
                  retryDelay: () => null,
                  queryString: (_search, raw) => {
                    const index = raw.indexOf('?');
                    return index < 0 ? '' : raw.slice(index + 1);
                  },
                  rewriteRequestHeaders(request, headers) {
                    const scope = requests.get(request)!;
                    scope.check();
                    const output = contentHeaders(headers, 'request');
                    if (scope.credential) output.authorization = scope.credential;
                    injectTrace(observed.telemetry, output);
                    return output;
                  },
                  rewriteHeaders: (headers) => contentHeaders(headers, 'response'),
                  onError(reply, { error }) {
                    const scope = requests.get(reply.request)!;
                    scope.fail(translated(error).code);
                    scope.respond();
                  },
                  onResponse(request, reply, response) {
                    const scope = requests.get(request)!;
                    try {
                      scope.check();
                      const length = response.headers['content-length'];
                      if (
                        length !== undefined &&
                        (!/^\d+$/.test(String(length)) || Number(length) > route.maxResponseBytes)
                      )
                        throw scope.fail('EK_PROXY_BODY_LIMIT');
                      const limiter = scope.limiter('response');
                      response.stream.once('error', (error) => {
                        scope.fail(translated(error).code);
                        scope.respond();
                      });
                      limiter.once('error', () => {
                        response.stream.unpipe(limiter);
                        response.stream.destroy();
                        scope.respond();
                      });
                      response.stream.pipe(limiter);
                      void reply.send(limiter);
                    } catch (error) {
                      scope.fail(translated(error).code);
                      response.stream.destroy();
                      scope.respond();
                    }
                  },
                },
              });
            },
            { logLevel: 'silent' },
          );
        }
        const service: ProxyService = Object.freeze({
          stats: () => Object.freeze({ ...counters }),
          health: () =>
            Object.freeze({
              configuredRoutes: settings.routes.length,
              ready: !closed && !owner.aborted && ready(),
            }),
        });
        context.provide(PROXY_CAPABILITY, service);
      } catch (error) {
        await close();
        throw error;
      }
    },
    async [DRAIN_PLUGIN](context) {
      await instances.get(context)?.close();
    },
    async close(context) {
      try {
        await instances.get(context)?.close();
      } finally {
        instances.delete(context);
      }
    },
  };
  return plugin;
}
