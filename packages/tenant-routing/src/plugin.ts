// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder, types } from 'node:util';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { APPLICATION_SIGNAL, COMPONENTS, KitError } from '@arkenivajs/core';
import type {
  AuthService,
  Plugin,
  PluginContext,
  RouteContext,
  VerifiedTenantContext,
  OperationOptions,
} from '@arkenivajs/core';
import {
  PREPARE_PLUGIN,
  DRAIN_PLUGIN,
  SUPPORT_PLUGINS,
  captureAbortSignal,
  within,
} from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { ManagedApiServer } from '@arkenivajs/api';
import { SQL_SUPPORT_ID } from '@arkenivajs/database/support';
import type {
  TenantRoutingPluginSettings,
  TenantRoutingService,
  TenantCapabilitiesResponse,
} from './contracts.js';
import { captureSettings, type Settings } from './settings.js';
import { captureMethod, data } from './provider-support.js';
import { routingFailure } from './errors.js';
import { RoutingOperation } from './operation.js';
import { verifiedTenant, authorized } from './identity.js';
import { jsonSnapshot } from './json.js';
import { TENANT_ROUTING_CAPABILITY } from './index.js';
import type { HttpUpstreams } from './http.js';
import { OBSERVERS, observations, Observation, elapsed, traceRequest } from './observation.js';
import type { Observers } from './observation.js';
import { RequestUsage } from './usage.js';
import type { RoutingEvents } from './events.js';

const AUTH = Symbol('tenant-routing.authority');
const STORAGE = Symbol('tenant-routing.storage-readiness');
const storage =
  (settings: Settings): SupportPluginFactory =>
  (options) => {
    const owners =
      options.plugins?.filter((plugin) =>
        ['database.postgresql', 'database.mysql', 'database.mariadb', 'database.oracle'].some(
          (capability) => plugin.capabilities.has(capability),
        ),
      ) ?? [];
    return {
      id: 'tenant-routing-storage',
      version: '0.1.0',
      capabilities: new Set(),
      dependencies: [
        ...new Set([
          ...owners.map((owner) => owner.id),
          ...(owners.length ? [SQL_SUPPORT_ID] : []),
        ]),
      ],
      async init(context) {
        const signal = context.require<AbortSignal>(APPLICATION_SIGNAL);
        try {
          const snapshot = await within(
            () => settings.registry.loadSnapshot({ signal, timeoutMs: 30000 }),
            { signal, timeoutMs: 30000 },
          );
          signal.throwIfAborted();
          context.provide(STORAGE, snapshot);
        } catch {
          throw routingFailure('EK_TROUTE_REGISTRY');
        }
      },
      close() {},
    };
  };
const authority: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('auth'));
  return {
    id: 'tenant-routing-authority',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      if (!owner) throw routingFailure();
      const original = context.require<AuthService>(COMPONENTS.auth);
      const captured: AuthService = Object.freeze({
        verifyBearer: captureMethod<AuthService['verifyBearer']>(original, 'verifyBearer'),
        requireScope: captureMethod<AuthService['requireScope']>(original, 'requireScope'),
        requireAssurance: captureMethod<AuthService['requireAssurance']>(
          original,
          'requireAssurance',
        ),
        tenantFrom: captureMethod<AuthService['tenantFrom']>(original, 'tenantFrom'),
      });
      context.provide(AUTH, { auth: captured, original });
    },
    close() {},
  };
};
const normalize = (path: string) => path.replace(/:[A-Za-z_][A-Za-z0-9_]*/g, ':parameter');
function bag(input: unknown): unknown {
  if (!input || typeof input !== 'object' || types.isProxy(input) || Array.isArray(input))
    return input;
  return Object.create(null, Object.getOwnPropertyDescriptors(input)) as unknown;
}
function headers(request: FastifyRequest): Readonly<Record<string, string | undefined>> {
  const output: Record<string, string | undefined> = Object.create(null) as Record<
    string,
    string | undefined
  >;
  let bytes = 0;
  for (const [key, source] of Object.entries(request.headers)) {
    const value = Array.isArray(source) ? source.join(',') : source;
    if (value !== undefined) {
      bytes += Buffer.byteLength(key) + Buffer.byteLength(value);
      if (bytes > 32768) throw routingFailure('EK_AUTH_REQUIRED');
    }
    output[key] = value;
  }
  let bearerHeaders = 0;
  for (let index = 0; index < request.raw.rawHeaders.length; index += 2)
    if (request.raw.rawHeaders[index]!.toLowerCase() === 'authorization') bearerHeaders++;
  if (bearerHeaders > 1) throw routingFailure('EK_AUTH_REQUIRED');
  return Object.freeze(output);
}
function reject(reply: FastifyReply, error: unknown, requestId: string) {
  if (reply.sent) return reply;
  const native =
    error && typeof error === 'object'
      ? Object.getOwnPropertyDescriptor(error, 'code')?.value
      : undefined;
  const code =
    error instanceof KitError
      ? error.code
      : typeof native === 'string' &&
          [
            'FST_ERR_CTP_BODY_TOO_LARGE',
            'FST_ERR_CTP_INVALID_MEDIA_TYPE',
            'FST_ERR_CTP_INVALID_CONTENT_LENGTH',
            'FST_ERR_CTP_EMPTY_JSON_BODY',
            'FST_ERR_VALIDATION',
          ].includes(native)
        ? 'EK_TROUTE_CONTRACT'
        : 'EK_TROUTE_UPSTREAM';
  let status = 503;
  if (code === 'EK_AUTH_REQUIRED') status = 401;
  else if (code === 'EK_TROUTE_FORBIDDEN') status = 403;
  else if (code === 'EK_TROUTE_UNMAPPED' || code === 'EK_TROUTE_DISABLED') status = 404;
  else if (code === 'EK_TROUTE_CONTRACT')
    status = error instanceof KitError && error.details.response === true ? 502 : 400;
  else if (code === 'EK_TROUTE_TIMEOUT') status = 504;
  const safe = routingFailure(code);
  return reply
    .code(status)
    .type('application/json')
    .send(JSON.stringify({ error: { code: safe.code, message: safe.message, requestId } }));
}

/** Register startup-compiled tenant routes on the existing application listener. */
export function tenantRoutingPlugin(input: TenantRoutingPluginSettings): Plugin {
  const settings = captureSettings(input),
    readiness = new WeakMap<object, () => boolean>();
  const instances = new WeakMap<
    PluginContext,
    { drain(): Promise<void>; close(): Promise<void> }
  >();
  const plugin: ComposablePlugin = {
    id: 'tenant-routing',
    version: '0.1.0',
    capabilities: new Set(['tenant-routing']),
    dependencies: [
      'api',
      'tenant-routing-authority',
      'tenant-routing-storage',
      'tenant-routing-observation',
    ],
    [SUPPORT_PLUGINS]: [authority, storage(settings), observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      if (!context.options.http) throw routingFailure();
      // Declared SQL adapters initialize before the configured registry loader runs.
      const snapshot = context.require<unknown>(STORAGE);
      const { auth, original } = context.require<{ auth: AuthService; original: AuthService }>(
          AUTH,
        ),
        owner = context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready = readiness.get(context.options);
      if (!ready) throw routingFailure();
      if (owner.aborted) throw routingFailure('EK_TROUTE_REGISTRY');
      const observers = context.require<Observers>(OBSERVERS),
        registryBegan = performance.now();
      let upstreams: HttpUpstreams | undefined,
        events: RoutingEvents | undefined,
        installed = false;
      try {
        const [{ RoutingTable }, { parseRegistryJson, validateRegistry }] = await Promise.all([
          import('./table.js'),
          import('./registry.js'),
        ]);
        const validated = validateRegistry(snapshot, 134217728);
        if (settings.approvedUpstreams.length) {
          const { HttpUpstreams } = await import('./http.js');
          upstreams = await HttpUpstreams.create(
            settings,
            context.options.service.environment,
            owner,
            observers,
          );
        }
        const table = new RoutingTable(validated, settings, upstreams);
        if (settings.eventExporter) {
          const { RoutingEvents } = await import('./events.js');
          events = new RoutingEvents(settings.eventExporter, observers);
        }
        elapsed(observers.telemetry, 'arkenivajs.routing.registry.duration', registryBegan);
        if (table.definitions.some((operation) => operation.policy.assurance !== undefined)) {
          let allowed = false;
          try {
            allowed = captureMethod<() => boolean>(original, 'hasAssurancePolicy')() === true;
          } catch {
            /* An unavailable assurance authority cannot admit protected routes. */
          }
          if (!allowed) throw routingFailure();
        }
        const server = context.require<ManagedApiServer>(COMPONENTS.api).native(),
          ownership = Symbol('tenant-routing.routes'),
          active = new Set<RoutingOperation>();
        const counters = {
          operations: table.definitions.length,
          bindings: table.snapshot.bindings.length,
          requests: 0,
          rejected: 0,
          unavailable: 0,
        };
        let closed = false,
          draining = false;
        const open = () => {
          if (closed) throw routingFailure('EK_RESOURCE_CLOSED');
          if (draining || !ready()) throw routingFailure('EK_LIFECYCLE_STATE');
        };
        const scope = (timeoutMs: number, signal = owner) => {
          if (active.size >= 1024) throw routingFailure('EK_TROUTE_CAPACITY');
          const operation = new RoutingOperation(timeoutMs, signal);
          active.add(operation);
          void operation.completion.then(() => active.delete(operation));
          return operation;
        };
        const project = async (
          tenant: VerifiedTenantContext,
          operation: RoutingOperation,
        ): Promise<TenantCapabilitiesResponse> => {
          verifiedTenant(auth, tenant);
          const capabilities: TenantCapabilitiesResponse['capabilities'][number][] = [];
          for (const selected of table.candidates(tenant.tenantId)) {
            operation.check();
            if (!(await authorized(auth, settings, tenant, selected.operation, operation))) {
              try {
                context.logger.debug('Tenant capability omitted by authorization', {
                  operationId: selected.operation.id,
                });
              } catch {
                /* Diagnostic failures cannot turn a denied capability into permission. */
              }
              continue;
            }
            const value = selected.operation;
            capabilities.push(
              Object.freeze({
                operationId: value.id,
                method: value.method,
                path: value.path,
                label: value.label,
              }),
            );
            if (capabilities.length > settings.maxCapabilities)
              throw routingFailure('EK_TCAP_LIMIT_EXCEEDED');
          }
          return Object.freeze({
            schemaVersion: '1.0.0',
            revision: table.snapshot.revision,
            activationGeneration: table.snapshot.activationGeneration,
            capabilities: Object.freeze(capabilities),
          });
        };
        const service: TenantRoutingService = Object.freeze({
          ...(events
            ? {
                events: Object.freeze({
                  stats() {
                    open();
                    return events!.stats();
                  },
                  async flush(options?: OperationOptions) {
                    open();
                    await events!.flush(options);
                  },
                }),
              }
            : {}),
          api: Object.freeze({
            resolve(operationId: string, tenant: VerifiedTenantContext) {
              open();
              verifiedTenant(auth, tenant);
              const selected = table.select(operationId, tenant.tenantId);
              return selected
                ? Object.freeze({
                    operationId: selected.operation.id,
                    implementationId: selected.implementation.id,
                    revision: table.snapshot.revision,
                    activationGeneration: table.snapshot.activationGeneration,
                    kind: selected.implementation.kind,
                  })
                : null;
            },
            revision() {
              open();
              return table.snapshot.revision;
            },
            operations() {
              open();
              return Object.freeze(table.definitions.map((item) => item.id).sort());
            },
          }),
          capabilities: Object.freeze({
            async list(tenant: VerifiedTenantContext, input: OperationOptions = {}) {
              open();
              const options = data(input, ['signal', 'timeoutMs']),
                timeout = options.timeoutMs === undefined ? 30000 : options.timeoutMs;
              if (!Number.isSafeInteger(timeout) || (timeout as number) < 1)
                throw routingFailure('EK_TCAP_UNAVAILABLE');
              const signal =
                options.signal === undefined
                  ? owner
                  : AbortSignal.any([owner, captureAbortSignal(options.signal)]);
              const operation = scope(timeout as number, signal);
              try {
                return await operation.run(() => project(tenant, operation));
              } catch (error) {
                if (error instanceof KitError && error.code === 'EK_TROUTE_TIMEOUT')
                  throw routingFailure(signal.aborted ? 'EK_ABORTED' : 'EK_TIMEOUT');
                throw error;
              } finally {
                operation.end();
              }
            },
          }),
          stats() {
            open();
            return Object.freeze({ ...counters });
          },
        });
        const wait = () =>
          Promise.all([...active].map((operation) => operation.completion)).then(() => undefined);
        instances.set(context, {
          async drain() {
            draining = true;
            if (owner.aborted) return;
            if (active.size) await within(wait, { signal: owner, timeoutMs: 30000 });
            await events?.flush({ signal: owner, timeoutMs: 5000 });
          },
          async close() {
            closed = true;
            draining = true;
            for (const operation of active) {
              operation.abort();
              operation.end();
            }
            try {
              if (!active.size || owner.aborted) return;
              await within(wait, { signal: owner, timeoutMs: 30000 });
            } finally {
              try {
                await upstreams?.close();
              } finally {
                await events?.close();
              }
            }
          },
        });
        const declared = table.definitions.map((operation) => ({
          method: operation.method,
          path: normalize(operation.path),
        }));
        for (const route of [...declared, { method: 'GET', path: settings.capabilitiesPath }]) {
          const methods = route.method === 'GET' ? ['GET', 'HEAD'] : [route.method];
          if (
            methods.some((method) => server.hasRoute({ method: method as 'GET', url: route.path }))
          )
            throw routingFailure('EK_TROUTE_COLLISION');
        }
        server.addHook('onRoute', (options) => {
          const methods = Array.isArray(options.method) ? options.method : [options.method],
            path = normalize(options.url);
          if (
            (path === settings.capabilitiesPath ||
              declared.some(
                (route) =>
                  route.path === path &&
                  methods.some(
                    (method) =>
                      method === route.method || (method === 'HEAD' && route.method === 'GET'),
                  ),
              )) &&
            (options.config as Record<symbol, unknown> | undefined)?.[ownership] !== true
          )
            throw routingFailure('EK_TROUTE_COLLISION');
        });
        server.register(async (child: FastifyInstance) => {
          const observed = new WeakMap<FastifyRequest, Observation>();
          const metered = new WeakMap<FastifyRequest, RequestUsage>();
          const routedEvents = new WeakMap<FastifyRequest, ReturnType<RoutingEvents['track']>>();
          const requestBytes = new WeakMap<FastifyRequest, number>();
          child.addHook('onRequest', async (request, reply) => {
            const observation = new Observation(
              observers,
              request.routeOptions.url === settings.capabilitiesPath,
            );
            observed.set(request, observation);
            reply.raw.once('close', () => {
              if (!reply.raw.writableEnded) {
                observation.finish(499);
                metered.get(request)?.finish(499);
                routedEvents.get(request)?.finish(499);
              }
            });
          });
          child.removeAllContentTypeParsers();
          child.addContentTypeParser(
            'application/json',
            { parseAs: 'buffer' },
            (request, body, done) => {
              try {
                if (!Buffer.isBuffer(body)) throw routingFailure('EK_TROUTE_CONTRACT');
                requestBytes.set(request, body.length);
                const maximum = request.routeOptions.bodyLimit;
                const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(
                  body,
                );
                done(null, jsonSnapshot(parseRegistryJson(text, maximum), maximum));
              } catch {
                done(routingFailure('EK_TROUTE_CONTRACT'));
              }
            },
          );
          const scopes = new WeakMap<
            FastifyRequest,
            {
              operation: RoutingOperation;
              tenant: VerifiedTenantContext;
              headers: Readonly<Record<string, string | undefined>>;
              clean: () => void;
            }
          >();
          child.setErrorHandler((error, request, reply) => reject(reply, error, request.id));
          child.addHook('onSend', async (request, _reply, payload) => {
            metered.get(request)?.response(payload);
            return payload;
          });
          child.addHook('onResponse', async (request, reply) => {
            observed.get(request)?.finish(reply.statusCode);
            observed.delete(request);
            const entry = scopes.get(request);
            entry?.operation.end();
            routedEvents.get(request)?.finish(reply.statusCode);
            routedEvents.delete(request);
            metered.get(request)?.finish(reply.statusCode);
            metered.delete(request);
            entry?.clean();
            scopes.delete(request);
            if (reply.statusCode >= 400)
              counters.rejected = Math.min(Number.MAX_SAFE_INTEGER, counters.rejected + 1);
            if (reply.statusCode === 404 || reply.statusCode === 503)
              counters.unavailable = Math.min(Number.MAX_SAFE_INTEGER, counters.unavailable + 1);
          });
          const authenticate =
            (timeoutMs: number) => async (request: FastifyRequest, reply: FastifyReply) => {
              open();
              counters.requests = Math.min(Number.MAX_SAFE_INTEGER, counters.requests + 1);
              const captured = headers(request),
                operation = scope(timeoutMs);
              const aborted = () => {
                operation.abort();
                operation.end();
              };
              const responseClosed = () => {
                if (!reply.raw.writableEnded) aborted();
              };
              request.raw.once('aborted', aborted);
              reply.raw.once('close', responseClosed);
              const expired = () => {
                if (
                  !scopes.has(request) ||
                  reply.sent ||
                  request.raw.destroyed ||
                  reply.raw.destroyed
                )
                  return;
                reply.raw.once('finish', () => request.raw.destroy());
                reject(reply, routingFailure('EK_TROUTE_TIMEOUT'), request.id);
              };
              operation.signal.addEventListener('abort', expired, { once: true });
              const clean = () => {
                operation.signal.removeEventListener('abort', expired);
                request.raw.off('aborted', aborted);
                reply.raw.off('close', responseClosed);
              };
              try {
                const identity = await operation.run(() =>
                  auth.verifyBearer(captured.authorization, {
                    signal: operation.signal,
                    timeoutMs,
                  }),
                );
                const tenant = verifiedTenant(auth, auth.tenantFrom(identity));
                scopes.set(request, { operation, tenant, headers: captured, clean });
              } catch (error) {
                operation.end();
                clean();
                if (error instanceof KitError && error.code === 'EK_TROUTE_TIMEOUT') throw error;
                throw routingFailure('EK_AUTH_REQUIRED');
              }
            };
          for (const definition of table.definitions) {
            child.route({
              method: definition.method,
              url: definition.path,
              bodyLimit: definition.maxBodyBytes,
              config: { [ownership]: true },
              onRequest: authenticate(definition.timeoutMs),
              async handler(request, reply) {
                const entry = scopes.get(request);
                if (!entry) throw routingFailure('EK_AUTH_REQUIRED');
                return traceRequest(
                  observers,
                  request.method,
                  definition.path,
                  entry.headers,
                  async () => {
                    const { operation, tenant } = entry;
                    const usage = new RequestUsage(
                      observers,
                      operation,
                      tenant,
                      request.id,
                      requestBytes.get(request) ?? 0,
                    );
                    metered.set(request, usage);
                    return usage.http(async () => {
                      const observation = observed.get(request)!;
                      operation.check();
                      const lookupBegan = performance.now();
                      const selected = table.select(definition.id, tenant.tenantId);
                      observation.lookup(selected, lookupBegan);
                      if (!selected) throw routingFailure('EK_TROUTE_UNMAPPED');
                      if (events) {
                        let traceId: string | undefined;
                        try {
                          const candidate = (
                            observers.telemetry as
                              { currentTraceId?: () => string | undefined } | undefined
                          )?.currentTraceId?.();
                          if (typeof candidate === 'string' && /^[0-9a-f]{32}$/.test(candidate))
                            traceId = candidate;
                        } catch {
                          /* Trace correlation never supplies identity. */
                        }
                        routedEvents.set(
                          request,
                          events.track(
                            {
                              requestId: request.id,
                              ...(traceId ? { traceId } : {}),
                              tenantId: tenant.tenantId,
                              operationId: definition.id,
                              registryRevision: table.snapshot.revision,
                              registryActivationGeneration: table.snapshot.activationGeneration,
                              implementationId: selected.implementation.id,
                              implementationKind: selected.implementation.kind,
                            },
                            operation.completion,
                            () => observation.durationMs(),
                          ),
                        );
                      }
                      if (
                        !(await observation.authorize(() =>
                          authorized(auth, settings, tenant, definition, operation),
                        ))
                      )
                        throw routingFailure('EK_TROUTE_FORBIDDEN');
                      const context: RouteContext = Object.freeze({
                        requestId: request.id,
                        auth: tenant,
                        signal: operation.signal,
                        headers: entry.headers,
                        params: table.input(definition, 'params', bag(request.params)) as Record<
                          string,
                          string
                        >,
                        query: table.input(definition, 'query', bag(request.query)) as Record<
                          string,
                          unknown
                        >,
                        body: table.input(definition, 'body', request.body),
                      });
                      operation.own(table.acquire(definition.id));
                      let output: unknown;
                      try {
                        output = await operation.run(() =>
                          usage.operation(definition.id, () =>
                            observation.execute(
                              selected,
                              tenant,
                              table.snapshot.revision,
                              table.snapshot.activationGeneration,
                              async () => selected.handler(context),
                            ),
                          ),
                        );
                      } catch (error) {
                        usage.reject(error);
                        if (
                          error instanceof KitError &&
                          (error.code === 'EK_AUTH_REQUIRED' ||
                            error.code === 'EK_TROUTE_TIMEOUT' ||
                            (selected.implementation.kind === 'http' &&
                              error.code === 'EK_TROUTE_CONTRACT'))
                        )
                          throw error;
                        throw routingFailure('EK_TROUTE_UPSTREAM');
                      }
                      operation.check();
                      return reply
                        .type('application/json')
                        .send(table.response(definition, output));
                    });
                  },
                );
              },
            });
          }
          child.get(
            settings.capabilitiesPath,
            {
              config: { [ownership]: true },
              onRequest: async (request, reply) => {
                reply.header('cache-control', 'private, no-store');
                const existing = reply.getHeader('vary');
                reply.header(
                  'vary',
                  existing ? String(existing) + ', Authorization' : 'Authorization',
                );
                await authenticate(30000)(request, reply);
              },
            },
            async (request, reply) => {
              const entry = scopes.get(request);
              if (!entry) throw routingFailure('EK_AUTH_REQUIRED');
              if (Object.keys(request.query as object).length)
                throw routingFailure('EK_TROUTE_CONTRACT');
              return reply
                .type('application/json')
                .send(await entry.operation.run(() => project(entry.tenant, entry.operation)));
            },
          );
        });
        if (owner.aborted) throw routingFailure('EK_TROUTE_REGISTRY');
        context.provide(TENANT_ROUTING_CAPABILITY, service);
        installed = true;
      } finally {
        if (!installed) {
          try {
            await upstreams?.close();
          } finally {
            await events?.close();
          }
          instances.delete(context);
        }
      }
    },
    async [DRAIN_PLUGIN](context) {
      await instances.get(context)?.drain();
    },
    async close(context) {
      await instances.get(context)?.close();
      instances.delete(context);
    },
  };
  return plugin;
}
