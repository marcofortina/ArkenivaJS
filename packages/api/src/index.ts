// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { Server as NativeTlsServer, type TlsOptions } from 'node:tls';
import { validateServerTlsFiles, withServerTls } from './server-tls.js';
import Fastify from 'fastify';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import swagger from '@fastify/swagger';
import { KitError, COMPONENTS, APPLICATION_SIGNAL } from '@arkenivajs/core';
import type {
  ApiServer,
  RouteDefinition,
  RouteContext,
  ApiMiddleware,
  Application,
  ApplicationOptions,
  Logger,
  OperationOptions,
  Telemetry,
  UsageMeter,
  MeterSession,
  MeterResultStatus,
  HealthRegistry,
  ServerTlsFiles,
} from '@arkenivajs/core';
import {
  copyData,
  freezeData,
  compileSchema,
  within,
  PREPARE_PLUGIN,
  ACTIVATE_PLUGIN,
  DRAIN_PLUGIN,
  SEMVER_PATTERN,
  instrumentOperation,
  SUPPORT_PLUGINS,
} from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';

export type {
  ApiServer,
  RouteDefinition,
  RouteContext,
  RouteHandler,
  ApiMiddleware,
} from '@arkenivajs/core';
/** Safe request observations use route templates and measured serialized response bytes. */
export interface ApiObservation {
  readonly method: string;
  readonly route: string;
  readonly status: number;
  readonly durationMs: number;
  readonly responseBytes?: number;
}
/** Server policy is captured before registration; transport resources start explicitly. */
export interface ApiOptions {
  readonly service: ApplicationOptions['service'];
  readonly host?: string;
  readonly port?: number;
  readonly requestTimeoutMs?: number;
  readonly bodyLimitBytes?: number;
  readonly validateResponses?: boolean;
  readonly logger?: Logger;
  readonly auth?: NonNullable<Application['auth']>;
  readonly telemetry?: Telemetry;
  readonly meter?: UsageMeter;
  readonly health?: HealthRegistry;
  readonly readinessTimeoutMs?: number;
  readonly isReady?: () => boolean;
  readonly onObservation?: (event: ApiObservation) => void;
  readonly protocol?: 'http' | 'https';
  readonly http2?: boolean;
  readonly tls?: { readonly key: string; readonly cert: string } | ServerTlsFiles;
}
/** Managed standalone servers expose their actual bound address and bounded cleanup. */
export interface ManagedApiServer extends ApiServer {
  start(options?: OperationOptions): Promise<void>;
  close(options?: OperationOptions): Promise<void>;
  address(): string | undefined;
  stats(): Readonly<{
    completed: number;
    failed: number;
    active: number;
    observerFailures: number;
  }>;
  native(): FastifyInstance;
}
type Auth = NonNullable<Application['auth']>;
const SERVICES = Symbol('api.services');
/** Application composition owns listener selection; standalone servers retain explicit start semantics. */
const listenerModes = new WeakMap<ManagedApiServer, (enabled: boolean) => void>();
type InternalApi = ManagedApiServer & {
  [SERVICES](
    logger: Logger,
    auth?: Auth,
    telemetry?: Telemetry,
    meter?: UsageMeter,
    health?: HealthRegistry,
  ): void;
};
type ScopedMeter = UsageMeter & {
  run<T>(session: MeterSession, work: () => T): T;
  markMissing(
    session: MeterSession,
    reason: 'driver_bytes_unavailable' | 'downstream_unobserved',
  ): void;
};
type ContextualTelemetry = Telemetry & {
  withRemoteContext?: <T>(
    headers: Readonly<Record<string, string | undefined>>,
    work: () => T,
  ) => T;
  currentTraceId?: () => string | undefined;
};
const invalid = (message: string) => new KitError({ code: 'EK_CONFIG_INVALID', message });
const statusFor = (error: KitError): number => {
  switch (error.code) {
    case 'EK_HTTP_VALIDATION':
      return 400;
    case 'EK_AUTH_REQUIRED':
    case 'EK_AUTH_INVALID':
    case 'EK_MFA_INVALID':
      return 401;
    case 'EK_AUTH_FORBIDDEN':
    case 'EK_TENANT_UNVERIFIED':
    case 'EK_MFA_ASSURANCE_REQUIRED':
      return 403;
    case 'EK_HTTP_NOT_FOUND':
      return 404;
    case 'EK_HTTP_RATE_LIMIT':
    case 'EK_MFA_RATE_LIMIT':
      return 429;
    case 'EK_MFA_REPLAY':
    case 'EK_MFA_ALREADY_ENROLLED':
    case 'EK_MFA_CREDENTIAL_CONFLICT':
    case 'EK_MFA_COUNTER_REGRESSION':
      return 409;
    case 'EK_MFA_EXPIRED':
    case 'EK_MFA_ENROLLMENT_EXPIRED':
    case 'EK_MFA_CHALLENGE_EXPIRED':
      return 410;
    case 'EK_TIMEOUT':
      return error.details.upstream === true ? 504 : 408;
    case 'EK_ABORTED':
      return 408;
    case 'EK_BACKEND_UNAVAILABLE':
    case 'EK_HEALTH_NOT_READY':
    case 'EK_MFA_STORAGE':
      return 503;
    default:
      return 500;
  }
};
const sorted = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, entry]) => [key, sorted(entry)]),
  );
};
// Fastify uses safe query/parameter prototypes; preserve own descriptors before strict copying.
const routeBag = (value: unknown): unknown =>
  copyData(
    value && typeof value === 'object' && !Array.isArray(value)
      ? Object.create(null, Object.getOwnPropertyDescriptors(value))
      : value,
  );

/** EK-HTTP-001: Fastify routing with strict schemas and safe lifecycle/error boundaries. */
export function createApi(options: ApiOptions): ManagedApiServer {
  if (
    !options ||
    !options.service ||
    typeof options.service.name !== 'string' ||
    !/^[a-z][a-z0-9-]{0,62}(?![\s\S])/.test(options.service.name) ||
    typeof options.service.version !== 'string' ||
    !new RegExp(SEMVER_PATTERN).test(options.service.version) ||
    !['development', 'test', 'production'].includes(options.service.environment)
  )
    throw invalid('Invalid API service metadata');
  const host = options.host ?? '127.0.0.1',
    port = options.port ?? 8080;
  const timeout = options.requestTimeoutMs ?? 30_000,
    bodyLimit = options.bodyLimitBytes ?? 1_048_576,
    readinessTimeoutMs = options.readinessTimeoutMs ?? 2000;
  if (
    typeof host !== 'string' ||
    !host ||
    host.length > 253 ||
    /[\s/]/.test(host) ||
    !Number.isSafeInteger(port) ||
    port < 0 ||
    port > 65535 ||
    !Number.isSafeInteger(timeout) ||
    timeout <= 0 ||
    timeout > 2_147_483_647 ||
    !Number.isSafeInteger(bodyLimit) ||
    bodyLimit <= 0 ||
    bodyLimit > 67_108_864 ||
    !Number.isSafeInteger(readinessTimeoutMs) ||
    readinessTimeoutMs <= 0 ||
    readinessTimeoutMs > 10_000 ||
    (options.health !== undefined &&
      (!options.health ||
        typeof options.health.live !== 'function' ||
        typeof options.health.ready !== 'function')) ||
    (options.validateResponses !== undefined && typeof options.validateResponses !== 'boolean')
  )
    throw invalid('Invalid API transport policy');
  for (const callback of [options.isReady, options.onObservation])
    if (callback !== undefined && typeof callback !== 'function')
      throw invalid('Invalid API callback');
  const tls = options.tls === undefined ? undefined : freezeData(copyData(options.tls));
  if (
    (options.protocol !== undefined && !['http', 'https'].includes(options.protocol)) ||
    (options.protocol === 'http' && tls !== undefined) ||
    (options.protocol === 'https' && tls === undefined) ||
    (options.http2 !== undefined && (typeof options.http2 !== 'boolean' || tls === undefined)) ||
    (port === 0 && options.service.environment !== 'test')
  )
    throw new KitError({ code: 'EK_HTTP_TLS_CONFIG', message: 'Invalid HTTP transport selection' });
  if (options.http2 === true)
    throw new KitError({
      code: 'EK_UNSUPPORTED_CAPABILITY',
      message: 'HTTP/2 transport is not available',
    });
  let tlsFiles: Readonly<ServerTlsFiles> | undefined;
  let nativeTls: TlsOptions | undefined;
  if (tls !== undefined) {
    if (!tls || typeof tls !== 'object' || Array.isArray(tls))
      throw new KitError({
        code: 'EK_HTTP_TLS_CONFIG',
        message: 'Invalid server TLS configuration',
      });
    if ('certificateFile' in tls) {
      tlsFiles = validateServerTlsFiles(tls);
      nativeTls = {
        minVersion: tlsFiles.minVersion ?? 'TLSv1.2',
        requestCert: tlsFiles.clientCertificate === 'required',
        rejectUnauthorized: true,
      };
    } else {
      if (
        Object.keys(tls).some((key) => key !== 'key' && key !== 'cert') ||
        !('key' in tls) ||
        !('cert' in tls) ||
        typeof tls.key !== 'string' ||
        typeof tls.cert !== 'string' ||
        tls.key.length > 1048576 ||
        tls.cert.length > 1048576
      )
        throw new KitError({ code: 'EK_HTTP_TLS_CONFIG', message: 'Invalid legacy TLS material' });
      nativeTls = { key: tls.key, cert: tls.cert, minVersion: 'TLSv1.2' };
    }
  }
  options = Object.freeze({
    ...options,
    service: freezeData(copyData(options.service)),
    ...(tls === undefined ? {} : { tls }),
  });
  let logger = options.logger,
    auth = options.auth;
  let telemetry = options.telemetry;
  let meter = options.meter as ScopedMeter | undefined;
  let health = options.health;
  let readinessProbe: ReturnType<HealthRegistry['ready']> | undefined;
  let state: 'created' | 'starting' | 'ready' | 'closing' | 'closed' = 'created';
  let bindListener = true;
  let starting: Promise<void> | undefined, closing: Promise<void> | undefined;
  let document: Readonly<Record<string, unknown>> | undefined;
  const counters = { completed: 0, failed: 0, observerFailures: 0 };
  const active = new Set<AbortController>();
  const activeRoutes = new Map<string, number>();
  const entries = new WeakMap<
    FastifyRequest,
    {
      controller: AbortController;
      began: number;
      clean: () => void;
      responseBytes?: number;
      traceId?: string;
      meterSession?: MeterSession;
    }
  >();
  const finishMeter = (
    entry: NonNullable<ReturnType<typeof entries.get>>,
    status: MeterResultStatus,
  ) => {
    const session = entry.meterSession;
    if (!session) return;
    delete entry.meterSession;
    try {
      if (entry.responseBytes !== undefined)
        session.recordUsage('http.response.bytes', {
          unit: 'bytes',
          source: 'observed',
          value: entry.responseBytes,
        });
      else meter!.markMissing(session, 'driver_bytes_unavailable');
    } catch {
      counters.observerFailures++;
    }
    try {
      session.end(status);
    } catch {
      counters.observerFailures++;
    }
  };
  const middleware: Record<'postAuthentication' | 'preHandler', ApiMiddleware[]> = {
    postAuthentication: [],
    preHandler: [],
  };
  const routes: {
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    path: string;
    spec: RouteDefinition<unknown, unknown, unknown, unknown>;
  }[] = [];
  let server: FastifyInstance;
  try {
    server = Fastify({
      logger: false,
      requestIdHeader: false,
      genReqId: () => randomUUID(),
      bodyLimit,
      requestTimeout: timeout,
      return503OnClosing: false,
      onProtoPoisoning: 'error',
      onConstructorPoisoning: 'error',
      ...(nativeTls === undefined ? {} : { https: nativeTls }),
    });
  } catch (cause) {
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Invalid API transport configuration',
      cause,
    });
  }
  const accepting = () => state === 'ready' && (options.isReady?.() ?? true);
  const abortAll = () => {
    for (const controller of active)
      controller.abort(
        new KitError({ code: 'EK_ABORTED', message: 'Server shutdown deadline reached' }),
      );
    server.server.closeAllConnections();
  };
  const open = () => {
    if (state === 'closed' || state === 'closing')
      throw new KitError({ code: 'EK_RESOURCE_CLOSED', message: 'API server is closed' });
  };
  const registering = () => {
    open();
    if (state !== 'created')
      throw new KitError({ code: 'EK_LIFECYCLE_STATE', message: 'API registration is frozen' });
  };
  server.setValidatorCompiler(({ schema }) => {
    const validate = compileSchema(schema as object);
    return (data) =>
      validate(data)
        ? { value: data }
        : {
            error: new Error('Request schema validation failed'),
          };
  });
  server.addHook('onRequest', async (request, reply) => {
    const controller = new AbortController();
    active.add(controller);
    const route = request.routeOptions.url ?? 'unmatched';
    const key = request.method + ':' + route;
    const track = (delta: number) => {
      if (
        !telemetry ||
        ['/livez', '/readyz'].includes(route) ||
        !['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(request.method)
      )
        return;
      const count = (activeRoutes.get(key) ?? 0) + delta;
      if (count === 0) activeRoutes.delete(key);
      else activeRoutes.set(key, count);
      try {
        telemetry?.setGauge('http.server.active_requests', count, {
          route,
          method: request.method,
        });
      } catch {
        counters.observerFailures++;
      }
    };
    track(1);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      track(-1);
      request.raw.off('aborted', disconnected);
      reply.raw.off('close', responseClosed);
      active.delete(controller);
      entries.delete(request);
    };
    const disconnected = () => {
      if (!entries.has(request)) return;
      controller.abort(new KitError({ code: 'EK_ABORTED', message: 'Client disconnected' }));
      finishMeter(entries.get(request)!, 'aborted');
      release();
      counters.completed++;
      counters.failed++;
    };
    const responseClosed = () => {
      if (!reply.raw.writableEnded) disconnected();
    };
    request.raw.once('aborted', disconnected);
    reply.raw.once('close', responseClosed);
    entries.set(request, { controller, began: performance.now(), clean: release });
    if (!['/livez', '/readyz'].includes(request.routeOptions.url ?? '') && !accepting())
      throw new KitError({
        code: 'EK_BACKEND_UNAVAILABLE',
        message: 'Server is not accepting work',
      });
  });
  server.addHook('onSend', async (request, reply, payload) => {
    // Existing keep-alive requests finish their response, then relinquish the draining socket.
    if (state === 'closing') reply.header('connection', 'close');
    const entry = entries.get(request);
    if (entry && (request.method === 'HEAD' || [204, 304].includes(reply.statusCode)))
      entry.responseBytes = 0;
    else if (entry && (typeof payload === 'string' || Buffer.isBuffer(payload)))
      entry.responseBytes = Buffer.byteLength(payload);
    return payload;
  });
  server.addHook('onResponse', async (request, reply) => {
    const entry = entries.get(request);
    if (!entry) return;
    let completion: MeterResultStatus = reply.statusCode >= 400 ? 'error' : 'ok';
    try {
      const reason = entry.controller.signal.reason;
      if (
        reason instanceof KitError &&
        (reason.code === 'EK_ABORTED' ||
          (reason.code === 'EK_TIMEOUT' && reason.details.upstream !== true))
      )
        completion = 'aborted';
    } catch {
      counters.observerFailures++;
    }
    finishMeter(entry, completion);
    entry.clean();
    active.delete(entry.controller);
    entries.delete(request);
    counters.completed++;
    if (reply.statusCode >= 400) counters.failed++;
    const route = request.routeOptions.url ?? 'unmatched';
    const event = Object.freeze({
      method: request.method,
      route,
      status: reply.statusCode,
      durationMs: performance.now() - entry.began,
      ...(entry.responseBytes === undefined ? {} : { responseBytes: entry.responseBytes }),
    });
    if (telemetry && !['/livez', '/readyz'].includes(route)) {
      try {
        telemetry.recordHistogram('http.server.request.duration', event.durationMs / 1000, {
          route,
          method: request.method,
          status_code: reply.statusCode,
        });
        if (entry.responseBytes !== undefined)
          telemetry.recordHistogram('arkenivajs.http.body.bytes', entry.responseBytes, {
            route,
            direction: 'server.response',
          });
      } catch {
        counters.observerFailures++;
      }
    }
    try {
      options.onObservation?.(event);
    } catch {
      counters.observerFailures++;
    }
    logger?.info('HTTP request completed', {
      requestId: request.id,
      method: request.method,
      route,
      status: reply.statusCode,
      durationMs: event.durationMs,
      ...(entry.traceId ? { traceId: entry.traceId } : {}),
    });
  });
  server.setErrorHandler((error, request, reply) => {
    const native =
      error && typeof error === 'object' ? (error as { validation?: unknown; code?: unknown }) : {};
    const failure =
      error instanceof KitError
        ? error
        : new KitError({
            code:
              native.validation ||
              (typeof native.code === 'string' &&
                (native.code === 'FST_ERR_VALIDATION' || native.code.startsWith('FST_ERR_CTP_')))
                ? 'EK_HTTP_VALIDATION'
                : 'EK_INTERNAL',
            message: 'HTTP request failed',
            cause: error,
          });
    const status = statusFor(failure);
    if (failure.code === 'EK_MFA_RATE_LIMIT') {
      const retryAfterMs = failure.details.retryAfterMs;
      if (
        typeof retryAfterMs === 'number' &&
        Number.isSafeInteger(retryAfterMs) &&
        retryAfterMs > 0 &&
        retryAfterMs <= 86_400_000
      )
        reply.header('retry-after', String(Math.ceil(retryAfterMs / 1000)));
    }
    logger?.error('HTTP request failed', {
      requestId: request.id,
      status,
      error: failure.toSafeJSON(),
    });
    void reply.code(status).send({ error: { ...failure.toSafeJSON(), requestId: request.id } });
  });
  server.setNotFoundHandler(() => {
    throw new KitError({ code: 'EK_HTTP_NOT_FOUND', message: 'Route not found' });
  });

  const register = <P, Q, B, R>(
    method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
    path: string,
    definition: RouteDefinition<P, Q, B, R>,
  ): void => {
    registering();
    if (
      typeof path !== 'string' ||
      !path.startsWith('/') ||
      path.length > 2048 ||
      /[\r\n#]/.test(path) ||
      ['/livez', '/readyz'].includes(path) ||
      !definition ||
      typeof definition.handler !== 'function' ||
      !definition.schema?.response ||
      typeof definition.schema.response !== 'object' ||
      Array.isArray(definition.schema.response) ||
      typeof definition.auth?.required !== 'boolean' ||
      (definition.auth.scopes !== undefined &&
        (!Array.isArray(definition.auth.scopes) ||
          definition.auth.scopes.some(
            (scope) => typeof scope !== 'string' || !scope || scope.length > 128,
          ))) ||
      (!definition.auth.required && !!definition.auth.scopes?.length)
    )
      throw invalid('Invalid API route definition');
    if (Object.keys(definition).some((key) => !['schema', 'auth', 'handler'].includes(key)))
      throw invalid('Unknown API route field');
    if (
      Object.keys(definition.auth).some((key) => !['required', 'scopes', 'assurance'].includes(key))
    )
      throw invalid('Unknown API authorization field');
    if (
      definition.auth.assurance !== undefined &&
      (!definition.auth.required ||
        !['single-factor', 'mfa', 'phishing-resistant'].includes(definition.auth.assurance))
    )
      throw new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid route assurance policy' });
    if (
      routes.some(
        (route) =>
          route.method === method &&
          route.path.replace(/:[A-Za-z0-9_]+/g, ':parameter') ===
            path.replace(/:[A-Za-z0-9_]+/g, ':parameter'),
      )
    )
      throw invalid('Duplicate API route');
    const schema = freezeData(copyData(definition.schema));
    for (const value of Object.values(schema)) if (value !== undefined) compileSchema(value);
    routes.push({
      method,
      path,
      spec: {
        schema,
        auth: freezeData(copyData(definition.auth)),
        handler: (context) => definition.handler(context as RouteContext<P, Q, B>),
      },
    });
  };
  const api: InternalApi = {
    get: (path, spec) => register('GET', path, spec),
    post: (path, spec) => register('POST', path, spec),
    put: (path, spec) => register('PUT', path, spec),
    patch: (path, spec) => register('PATCH', path, spec),
    delete: (path, spec) => register('DELETE', path, spec),
    registerMiddleware(stage, fn) {
      registering();
      if (!['postAuthentication', 'preHandler'].includes(stage) || typeof fn !== 'function')
        throw invalid('Invalid API middleware');
      middleware[stage].push(fn);
    },
    native() {
      open();
      return server;
    },
    address() {
      const value = server.server.address();
      return value && typeof value === 'object'
        ? `${options.tls ? 'https' : 'http'}://${value.family === 'IPv6' ? '[' + value.address + ']' : value.address}:${value.port}`
        : undefined;
    },
    stats: () => Object.freeze({ ...counters, active: active.size }),
    openApiDocument() {
      open();
      if (!document)
        throw new KitError({
          code: 'EK_LIFECYCLE_STATE',
          message: 'OpenAPI is available after startup',
        });
      return document;
    },
    [SERVICES](nextLogger, nextAuth, nextTelemetry, nextMeter, nextHealth) {
      registering();
      logger = nextLogger;
      auth = nextAuth;
      telemetry = nextTelemetry;
      meter = nextMeter as ScopedMeter | undefined;
      health = nextHealth;
    },
    start(operation: OperationOptions = {}) {
      try {
        open();
      } catch (error) {
        return Promise.reject(error);
      }
      if (starting) return starting;
      if (meter && (typeof meter.run !== 'function' || typeof meter.markMissing !== 'function'))
        return Promise.reject(invalid('Automatic request metering requires owned scope controls'));
      if (routes.some((route) => route.spec.auth.assurance !== undefined)) {
        let configured = false;
        try {
          configured =
            (
              auth as (Auth & { hasAssurancePolicy?: () => boolean }) | undefined
            )?.hasAssurancePolicy?.() === true && typeof auth?.requireAssurance === 'function';
        } catch {
          /* A failed provider capability check cannot permit an assurance-protected listener. */
        }
        if (!configured)
          return Promise.reject(
            new KitError({
              code: 'EK_MFA_POLICY',
              message: 'Assurance-protected routes require a trusted resolver',
            }),
          );
      }
      if (routes.some((route) => route.spec.auth.required) && !auth)
        return Promise.reject(
          new KitError({
            code: 'EK_PLUGIN_DEPENDENCY',
            message: 'Protected routes require an authentication provider',
          }),
        );
      state = 'starting';
      starting = within(async () => {
        if (bindListener && tlsFiles) {
          const native = server.server;
          if (!(native instanceof NativeTlsServer))
            throw new KitError({
              code: 'EK_HTTP_TLS_CONFIG',
              message: 'The selected server cannot load a TLS context',
            });
          await withServerTls(tlsFiles, (material) => native.setSecureContext(material));
          if (operation.signal?.aborted || state !== 'starting')
            throw new KitError({ code: 'EK_ABORTED', message: 'API activation aborted' });
        }
        await server.register(swagger, {
          openapi: {
            openapi: '3.1.0',
            info: { title: options.service.name, version: options.service.version },
            components: {
              securitySchemes: {
                bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
              },
            },
          },
        });
        for (const { method, path, spec } of routes) {
          const validate = compileSchema(spec.schema.response);
          server.route({
            method,
            url: path,
            schema: {
              ...(spec.schema.params ? { params: spec.schema.params } : {}),
              ...(spec.schema.query ? { querystring: spec.schema.query } : {}),
              ...(spec.schema.body ? { body: spec.schema.body } : {}),
              response: { 200: spec.schema.response },
              security: spec.auth.required ? [{ bearerAuth: [] }] : [],
              ...(spec.auth.assurance ? { 'x-arkenivajs-assurance': spec.auth.assurance } : {}),
            },
            async handler(request) {
              const entry = entries.get(request)!;
              const invoke = async () => {
                try {
                  return await within(
                    async () => {
                      let tenant;
                      if (spec.auth.required) {
                        const identity = await auth!.verifyBearer(request.headers.authorization, {
                          signal: entry.controller.signal,
                          timeoutMs: timeout,
                        });
                        for (const scope of spec.auth.scopes ?? [])
                          auth!.requireScope(identity, scope);
                        if (spec.auth.assurance !== undefined)
                          auth!.requireAssurance(identity, spec.auth.assurance);
                        tenant = auth!.tenantFrom(identity);
                      }
                      if (tenant && meter) {
                        try {
                          entry.meterSession = meter.start({
                            tenant,
                            operation: request.method + ' ' + path,
                            requestId: request.id,
                          });
                          entry.meterSession.recordOperation('http.requests');
                        } catch (error) {
                          if (error instanceof KitError && error.code === 'EK_TENANT_UNVERIFIED')
                            throw error;
                          counters.observerFailures++;
                        }
                      }
                      const headers = Object.fromEntries(
                        Object.entries(request.headers).map(([name, value]) => [
                          name,
                          Array.isArray(value) ? value.join(',') : value,
                        ]),
                      );
                      const context: RouteContext<unknown, unknown, unknown> = Object.freeze({
                        requestId: request.id,
                        params: freezeData(routeBag(request.params)),
                        query: freezeData(routeBag(request.query)),
                        body: freezeData(copyData(request.body)),
                        signal: entry.controller.signal,
                        headers: Object.freeze(headers),
                        ...(tenant ? { auth: tenant } : {}),
                      });
                      const chain = [...middleware.postAuthentication, ...middleware.preHandler];
                      let last = -1;
                      let result: unknown;
                      const dispatch = async (index: number): Promise<void> => {
                        if (index <= last)
                          throw new KitError({
                            code: 'EK_LIFECYCLE_STATE',
                            message: 'Middleware next may run only once',
                          });
                        last = index;
                        if (index === chain.length) {
                          result = await spec.handler(context);
                          return;
                        }
                        let continued = false;
                        await chain[index]!(context as RouteContext, async () => {
                          continued = true;
                          await dispatch(index + 1);
                        });
                        if (!continued)
                          throw new KitError({
                            code: 'EK_LIFECYCLE_STATE',
                            message: 'Middleware must continue or throw a typed error',
                          });
                      };
                      const execute = async () => {
                        await dispatch(0);
                        if (options.validateResponses !== false && !validate(result))
                          throw new KitError({
                            code: 'EK_INTERNAL',
                            message: 'Handler response schema validation failed',
                          });
                        return result;
                      };
                      return entry.meterSession
                        ? meter!.run(entry.meterSession, execute)
                        : execute();
                    },
                    { timeoutMs: timeout, signal: entry.controller.signal },
                  );
                } catch (error) {
                  entry.controller.abort(error);
                  throw error;
                }
              };
              const contextual = logger as
                | (Logger & {
                    run?: <T>(fields: Readonly<Record<string, unknown>>, work: () => T) => T;
                  })
                | undefined;
              const traced = telemetry as ContextualTelemetry | undefined;
              const work = () =>
                instrumentOperation(
                  telemetry,
                  'http.server.request',
                  { route: path, method: request.method },
                  () => {
                    let traceId: string | undefined;
                    try {
                      traceId = traced?.currentTraceId?.();
                    } catch {
                      counters.observerFailures++;
                    }
                    if (traceId) entry.traceId = traceId;
                    return contextual?.run
                      ? contextual.run(
                          { requestId: request.id, ...(traceId ? { traceId } : {}) },
                          invoke,
                        )
                      : invoke();
                  },
                  () => {
                    counters.observerFailures++;
                  },
                );
              if (traced?.withRemoteContext) {
                let invoked = false;
                try {
                  const result = await traced.withRemoteContext(
                    Object.fromEntries(
                      Object.entries(request.headers).map(([name, value]) => [
                        name,
                        Array.isArray(value) ? value.join(',') : value,
                      ]),
                    ),
                    () => {
                      invoked = true;
                      return work();
                    },
                  );
                  if (invoked) return result;
                  counters.observerFailures++;
                } catch (error) {
                  if (invoked) throw error;
                  counters.observerFailures++;
                }
              }
              return work();
            },
          });
        }
        server.get('/livez', { schema: { hide: true } }, () => ({ status: 'live' }));
        server.get('/readyz', { schema: { hide: true } }, async (_request, reply) => {
          let ready = accepting();
          if (ready && health) {
            try {
              if (!readinessProbe) {
                const owner = health;
                const pending = Promise.resolve().then(() => owner.ready());
                readinessProbe = pending;
                const release = () => {
                  if (readinessProbe === pending) readinessProbe = undefined;
                };
                void pending.then(release, release);
              }
              const pending = readinessProbe;
              const result = await within(() => pending, { timeoutMs: readinessTimeoutMs });
              ready =
                result.status === 'ready' &&
                Array.isArray(result.failing) &&
                result.failing.length === 0;
            } catch {
              ready = false;
            }
          }
          ready = ready && accepting();
          if (!ready) void reply.code(503);
          return { status: ready ? 'ready' : 'not_ready' };
        });
        await server.ready();
        document = freezeData(sorted(copyData(server.swagger())) as Record<string, unknown>);
        const abort = () => {
          abortAll();
          void server.close().catch(() => undefined);
        };
        operation.signal?.addEventListener('abort', abort, { once: true });
        try {
          if (bindListener) {
            try {
              await server.listen({ host, port });
            } catch (cause) {
              throw new KitError({
                code: 'EK_HTTP_LISTEN',
                message: 'HTTP listener could not bind',
                cause,
              });
            }
          }
          if (operation.signal?.aborted || state === 'closed' || state === 'closing') {
            abort();
            throw new KitError({ code: 'EK_ABORTED', message: 'API activation aborted' });
          }
          state = 'ready';
        } finally {
          operation.signal?.removeEventListener('abort', abort);
        }
      }, operation).catch((cause: unknown) => {
        abortAll();
        state = 'closed';
        void server.close().catch(() => undefined);
        if (cause instanceof KitError) throw cause;
        throw new KitError({
          code: 'EK_BACKEND_UNAVAILABLE',
          message: 'API listener could not start',
          cause,
        });
      });
      return starting;
    },
    close(operation: OperationOptions = {}) {
      if (closing) return closing;
      if (state === 'closed') return Promise.resolve();
      state = 'closing';
      const abort = () => abortAll();
      operation.signal?.addEventListener('abort', abort, { once: true });
      if (operation.signal?.aborted) abort();
      const nativeClose = server.close();
      void nativeClose.catch(() => undefined);
      closing = within(() => nativeClose, operation)
        .catch((error: unknown) => {
          abortAll();
          throw error;
        })
        .finally(() => {
          operation.signal?.removeEventListener('abort', abort);
          state = 'closed';
        });
      return closing;
    },
  };
  listenerModes.set(api, (enabled) => {
    registering();
    bindListener = enabled;
  });
  return Object.freeze(api);
}

/** Explicit plugin dependencies authorize access to authentication and future integrations. */
export interface ApiPluginOptions extends Omit<
  ApiOptions,
  | 'service'
  | 'host'
  | 'port'
  | 'requestTimeoutMs'
  | 'logger'
  | 'auth'
  | 'telemetry'
  | 'meter'
  | 'health'
> {
  readonly dependencies?: readonly string[];
}
const HEALTH_SERVICE = Symbol('api.health');
const healthSupport: SupportPluginFactory = (root) => {
  const owner = root.plugins?.find((plugin) => plugin.capabilities.has('health'));
  return {
    id: 'api-health',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      context.provide(
        HEALTH_SERVICE,
        Object.freeze(owner ? { health: context.require<HealthRegistry>(COMPONENTS.health) } : {}),
      );
    },
    close() {},
  };
};
/** Prepare route registration before start; activate the listener after every resource init. */
export function apiPlugin(options: ApiPluginOptions = {}): ComposablePlugin {
  return {
    id: 'api',
    version: '0.1.0',
    capabilities: new Set(['api']),
    dependencies: ['logging', 'api-health', ...(options.dependencies ?? [])],
    [SUPPORT_PLUGINS]: [healthSupport],
    [PREPARE_PLUGIN](context) {
      if (options.tls !== undefined && context.options.http !== undefined)
        throw new KitError({
          code: 'EK_HTTP_TLS_CONFIG',
          message: 'Application TLS must use its explicit HTTPS configuration',
        });
      const api = createApi({
        ...options,
        service: context.options.service,
        ...(context.options.http ?? {}),
        isReady: () => context.state() === 'READY' && (options.isReady?.() ?? true),
      });
      listenerModes.get(api)!(context.options.http !== undefined);
      return new Map([[COMPONENTS.api, api]]);
    },
    init(context) {
      const api = context.require<InternalApi>(COMPONENTS.api);
      api[SERVICES](
        context.logger,
        context.options.security ? context.require<Auth>(COMPONENTS.auth) : undefined,
        context.options.telemetry ? context.require<Telemetry>(COMPONENTS.telemetry) : undefined,
        context.options.metering?.enabled
          ? context.require<UsageMeter>(COMPONENTS.meter)
          : undefined,
        context.require<{ health?: HealthRegistry }>(HEALTH_SERVICE).health,
      );
    },
    async [ACTIVATE_PLUGIN](context) {
      await context
        .require<ManagedApiServer>(COMPONENTS.api)
        .start({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
    },
    async close(context) {
      await context
        .require<ManagedApiServer>(COMPONENTS.api)
        .close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
    },
    async [DRAIN_PLUGIN](context) {
      await context
        .require<ManagedApiServer>(COMPONENTS.api)
        .close({ signal: context.require<AbortSignal>(APPLICATION_SIGNAL) });
    },
  };
}
