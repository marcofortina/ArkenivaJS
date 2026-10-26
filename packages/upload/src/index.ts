// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { setImmediate as immediate } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import multipart from '@fastify/multipart';
import type { FastifyRequest } from 'fastify';
import type { ManagedApiServer } from '@arkenivajs/api';
import { APPLICATION_SIGNAL, COMPONENTS, KitError } from '@arkenivajs/core';
import type {
  AuthService,
  Plugin,
  RouteContext,
  Logger,
  Telemetry,
  VerifiedTenantContext,
  UsageMeter,
  MeterSession,
} from '@arkenivajs/core';
import {
  compileSchema,
  copyData,
  freezeData,
  SUPPORT_PLUGINS,
  DRAIN_PLUGIN,
} from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { UploadPluginSettings, UploadStats, UploadService } from './contracts.js';
import { capture, failure } from './policy.js';
import { RequestScope } from './runtime.js';
import { parts } from './parts.js';

export type * from './contracts.js';
/** Startup-only optional upload capability; importing it starts no parser or listener. */
export const UPLOAD_CAPABILITY: unique symbol = Symbol('arkenivajs.upload');
const OBSERVERS = Symbol('upload.observers');
interface Observers {
  readonly logger?: Logger;
  readonly telemetry?: Telemetry;
  readonly auth?: AuthService;
  readonly meter?: UsageMeter;
}
const observers: SupportPluginFactory = (options) => {
  const logging = options.plugins?.find((entry) => entry.capabilities.has('logger')),
    telemetry = options.plugins?.find((entry) => entry.capabilities.has('telemetry')),
    security = options.plugins?.find((entry) => entry.capabilities.has('auth')),
    metering = options.plugins?.find((entry) => entry.capabilities.has('meter'));
  return {
    id: 'upload-observers',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [
      ...new Set(
        [logging?.id, telemetry?.id, security?.id, metering?.id].filter(
          (id): id is string => id !== undefined,
        ),
      ),
    ],
    init(context) {
      context.provide<Observers>(OBSERVERS, {
        ...(logging ? { logger: context.require<Logger>(COMPONENTS.logger) } : {}),
        ...(telemetry ? { telemetry: context.require<Telemetry>(COMPONENTS.telemetry) } : {}),
        ...(security ? { auth: context.require<AuthService>(COMPONENTS.auth) } : {}),
        ...(metering && options.metering?.enabled
          ? { meter: context.require<UsageMeter>(COMPONENTS.meter) }
          : {}),
      });
    },
    close() {},
  };
};
function status(code: string): number {
  if (code === 'EK_UPLOAD_LIMIT') return 413;
  if (code === 'EK_UPLOAD_MEDIA_TYPE') return 415;
  if (['EK_AUTH_REQUIRED', 'EK_AUTH_INVALID'].includes(code)) return 401;
  if (['EK_AUTH_FORBIDDEN', 'EK_TENANT_UNVERIFIED'].includes(code)) return 403;
  if (code === 'EK_BACKEND_UNAVAILABLE') return 503;
  if (['EK_TIMEOUT', 'EK_ABORTED'].includes(code)) return 408;
  if (['EK_UPLOAD_STREAM', 'EK_UPLOAD_TRUNCATED', 'EK_HTTP_VALIDATION'].includes(code)) return 400;
  return 500;
}

/** Share the API listener and its native registry; consume incoming files only through bounded streams. */
export function uploadPlugin(input: UploadPluginSettings): Plugin {
  const routes = capture(input),
    instances = new WeakMap<object, { close(): Promise<void> }>();
  const plugin: ComposablePlugin = {
    id: 'upload',
    version: '0.1.0',
    capabilities: new Set(['upload']),
    dependencies: ['api', 'upload-observers'],
    [SUPPORT_PLUGINS]: [observers],
    init(context) {
      const observer = context.require<Observers>(OBSERVERS);
      if (routes.some((route) => route.auth.required) && !observer.auth) throw failure();
      const api = context.require<ManagedApiServer>(COMPONENTS.api),
        server = api.native(),
        owner = context.require<AbortSignal>(APPLICATION_SIGNAL),
        timeoutMs = context.options.http?.requestTimeoutMs ?? 30000,
        scopes = new Set<RequestScope>(),
        metered = new WeakMap<RequestScope, MeterSession>(),
        requests = new WeakMap<FastifyRequest, RequestScope>();
      const stats = {
        activeRequests: 0,
        receivedRequests: 0,
        successfulRequests: 0,
        rejectedRequests: 0,
        observedBytes: 0,
      };
      let closed = false;
      const safe = (work: () => unknown) => {
        try {
          void Promise.resolve(work()).catch(() => undefined);
        } catch {
          /* Observations never replay a handler. */
        }
      };
      const service: UploadService = Object.freeze({
        stats: (): UploadStats => Object.freeze({ ...stats }),
      });
      server.register(multipart, {
        attachFieldsToBody: false,
        preservePath: true,
        highWaterMark: 16384,
        fileHwm: 16384,
        throwFileSizeLimit: true,
      });
      for (const route of routes) {
        const validate = compileSchema(route.responseSchema),
          tenants = new WeakMap<FastifyRequest, VerifiedTenantContext>();
        const responseSchema = {
          response: { 200: route.responseSchema },
          consumes: ['multipart/form-data'],
          security: route.auth.required ? [{ bearerAuth: [] }] : [],
        };
        const complete = (request: FastifyRequest, accepted: boolean) => {
          const scope = requests.get(request);
          if (!scope) return;
          const success = accepted && scope.exhausted && !scope.error;
          if (success) stats.successfulRequests++;
          else stats.rejectedRequests++;
          const attributes = {
              'upload.method': route.method,
              'upload.outcome': success ? 'ok' : 'error',
            },
            durationMs = Math.max(0, performance.now() - scope.started);
          safe(() =>
            observer.logger?.debug('Multipart upload completed', {
              method: route.method,
              accepted: success,
              bytes: scope.bytes,
              files: scope.files,
              parts: scope.parts,
              durationMs,
            }),
          );
          safe(() =>
            observer.telemetry?.recordHistogram('upload.duration.ms', durationMs, attributes),
          );
          safe(() =>
            observer.telemetry?.addCounter('upload.request.bytes', scope.bytes, attributes),
          );
          safe(() => observer.telemetry?.addCounter('upload.files', scope.files, attributes));
          safe(() => {
            const meter = metered.get(scope);
            if (!meter) return;
            try {
              meter.recordUsage('upload.request.bytes', {
                unit: 'bytes',
                value: scope.bytes,
                source: 'observed',
              });
              meter.recordUsage('upload.files', {
                unit: 'items',
                value: scope.files,
                source: 'observed',
              });
              meter.recordUsage('upload.parts', {
                unit: 'items',
                value: scope.parts,
                source: 'observed',
              });
            } catch {
              safe(() => {
                const managed = observer.meter as UsageMeter & {
                  markMissing?: (session: MeterSession, reason: 'span_not_instrumented') => void;
                };
                managed.markMissing?.(meter, 'span_not_instrumented');
              });
              safe(() =>
                observer.logger?.warn('Upload technical usage definitions are unavailable'),
              );
            } finally {
              meter.end(
                success
                  ? 'ok'
                  : ['EK_ABORTED', 'EK_TIMEOUT', 'EK_UPLOAD_TRUNCATED'].includes(
                        scope.error?.code ?? '',
                      )
                    ? 'aborted'
                    : 'error',
              );
            }
            metered.delete(scope);
          });
          requests.delete(request);
          tenants.delete(request);
          scope.finish();
        };
        server.route<{ Reply: unknown }>({
          method: route.method,
          url: route.path,
          schema: responseSchema,
          async onRequest(request, reply) {
            stats.receivedRequests++;
            if (closed || scopes.size >= 32) {
              stats.rejectedRequests++;
              throw failure('EK_BACKEND_UNAVAILABLE');
            }
            const scope = new RequestScope(request, reply, owner, timeoutMs, () => {
              scopes.delete(scope);
              stats.activeRequests = scopes.size;
            });
            scopes.add(scope);
            stats.activeRequests = scopes.size;
            requests.set(request, scope);
            reply.raw.once('close', () => {
              if (!reply.raw.writableEnded) complete(request, false);
            });
            if (route.auth.required) {
              await scope.run(async () => {
                const identity = await observer.auth!.verifyBearer(
                  request.headers.authorization,
                  scope.options(),
                );
                for (const required of route.auth.required ? (route.auth.scopes ?? []) : [])
                  observer.auth!.requireScope(identity, required);
                scope.check();
                const tenant = observer.auth!.tenantFrom(identity);
                tenants.set(request, tenant);
                safe(() => {
                  if (observer.meter) {
                    const meter = observer.meter.start({
                      tenant,
                      operation: route.method + ' ' + route.path,
                      requestId: request.id,
                    });
                    metered.set(scope, meter);
                    meter.recordOperation('http.requests');
                  }
                });
              });
            }
          },
          preParsing(request, reply, payload, done) {
            const scope = requests.get(request)!;
            if (
              request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase() !==
              'multipart/form-data'
            ) {
              done(scope.fail('EK_UPLOAD_MEDIA_TYPE'));
              return;
            }
            // Multipart reads the original IncomingMessage. Observe it before the native parser;
            // replacing Fastify's preParsing payload would not bound this upstream parser.
            const count = (chunk: Buffer) => {
              scope.bytes += chunk.length;
              stats.observedBytes += chunk.length;
              try {
                scope.check();
                if (scope.bytes > route.policy.maxRequestBytes) throw scope.fail('EK_UPLOAD_LIMIT');
              } catch (cause) {
                scope.translate(cause);
                request.raw.pause();
                if (request.raw.httpVersionMajor === 1) reply.header('connection', 'close');
              }
            };
            request.raw.pause();
            request.raw.prependListener('data', count);
            scope.onCleanup(() => request.raw.off('data', count));
            request.raw.pause();
            done(null, payload);
          },
          async handler(request) {
            const scope = requests.get(request)!;
            return scope.run(async () => {
              if (!request.isMultipart()) throw scope.fail('EK_UPLOAD_MEDIA_TYPE');
              const tenant = tenants.get(request);
              const headers = Object.freeze(
                Object.fromEntries(
                  Object.entries(request.headers).map(([name, value]) => [
                    name,
                    Array.isArray(value) ? value.join(',') : value,
                  ]),
                ),
              );
              const routeContext: RouteContext = Object.freeze({
                requestId: request.id,
                params: freezeData(
                  copyData(Object.create(null, Object.getOwnPropertyDescriptors(request.params))),
                ) as RouteContext['params'],
                query: freezeData(
                  copyData(Object.create(null, Object.getOwnPropertyDescriptors(request.query))),
                ) as RouteContext['query'],
                body: undefined,
                signal: scope.signal,
                headers,
                ...(tenant ? { auth: tenant } : {}),
              });
              let result: unknown;
              try {
                result = await route.handler(
                  Object.freeze({
                    context: routeContext,
                    parts: parts(request, scope, route.policy),
                  }),
                );
              } catch (cause) {
                throw cause instanceof KitError ? cause : failure('EK_UPLOAD_STREAM');
              }
              scope.check();
              if (!scope.exhausted) throw scope.fail('EK_UPLOAD_TRUNCATED');
              const snapshot = copyData(result);
              if (!validate(snapshot)) throw failure('EK_HTTP_VALIDATION');
              return snapshot;
            });
          },
          errorHandler(cause, request, reply) {
            const scope = requests.get(request);
            const error =
              cause instanceof KitError
                ? cause
                : (scope?.translate(cause) ?? failure('EK_UPLOAD_STREAM'));
            if (scope && !scope.error) scope.fail(error.code);
            if (request.raw.httpVersionMajor === 1) reply.header('connection', 'close');
            void reply
              .code(status(error.code))
              .send({ error: { ...error.toSafeJSON(), requestId: request.id } });
          },
          async onResponse(request, reply) {
            complete(request, reply.statusCode < 400);
          },
        });
      }
      context.provide(UPLOAD_CAPABILITY, service);
      instances.set(context, {
        async close() {
          closed = true;
          for (const scope of scopes) {
            scope.fail('EK_RESOURCE_CLOSED');
            scope.finish();
          }
          while (scopes.size) {
            const pending = [...scopes].flatMap((scope) => [...scope.pending]);
            if (pending.length) await Promise.allSettled(pending);
            else await immediate();
          }
        },
      });
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
