// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder, toUSVString } from 'node:util';
import { getOperationAST, parse } from 'graphql';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { APPLICATION_SIGNAL, COMPONENTS, KitError } from '@arkenivajs/core';
import type { AuthService, Plugin, PluginContext } from '@arkenivajs/core';
import { DRAIN_PLUGIN, PREPARE_PLUGIN, SUPPORT_PLUGINS, within } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { ManagedApiServer } from '@arkenivajs/api';
import { GRAPHQL_CAPABILITY } from './index.js';
import type { GraphqlPluginSettings, GraphqlService, GraphqlRequestContext } from './contracts.js';
import { budget } from './budget.js';
import { protectFields } from './fields.js';
import { installLoaders } from './loaders.js';
import { installMetadata, assertMetadata, ownMetadata, authorizeMetadata } from './metadata.js';
import { Operation } from './operation.js';
import { capture, failure, record } from './policy.js';
import { compileSchema } from './schema.js';
import { encodeResult } from './encoding.js';
import { registerIde } from './ide.js';
import {
  OBSERVERS,
  Observation,
  observations,
  traceRequest,
  traceOperation,
} from './observation.js';
import type { Observers } from './observation.js';
import { RequestUsage } from './usage.js';

const AUTHORITY = Symbol('graphql.authority');
const authority: SupportPluginFactory = (options) => {
  const auth = options.plugins?.find((plugin) => plugin.capabilities.has('auth'));
  return {
    id: 'graphql-authority',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: auth ? [auth.id] : [],
    init(context) {
      context.provide(AUTHORITY, auth ? context.require<AuthService>(COMPONENTS.auth) : undefined);
    },
    close() {},
  };
};
const statuses: Readonly<Record<string, number>> = {
  EK_GQL_AUTH: 401,
  EK_GQL_FORBIDDEN: 403,
  EK_GQL_INPUT_LIMIT: 413,
  EK_GQL_TIMEOUT: 504,
  EK_GQL_RESPONSE_LIMIT: 500,
  EK_GQL_EXECUTION: 500,
};
function rejected(reply: FastifyReply, error: unknown, maximum: number) {
  const code =
    error instanceof KitError &&
    [
      'EK_GQL_AUTH',
      'EK_GQL_FORBIDDEN',
      'EK_GQL_INPUT_LIMIT',
      'EK_GQL_COMPLEXITY',
      'EK_GQL_VALIDATION',
      'EK_GQL_TIMEOUT',
      'EK_GQL_RESPONSE_LIMIT',
      'EK_GQL_EXECUTION',
    ].includes(error.code)
      ? error.code
      : 'EK_GQL_VALIDATION';
  const safe = failure(code);
  const encoded = JSON.stringify({ errors: [{ message: safe.message, extensions: { code } }] });
  reply.code(statuses[code] ?? 400);
  if (Buffer.byteLength(encoded) > maximum) return reply.send();
  return reply.type('application/json').send(encoded);
}

/** Register a guarded optional GraphQL endpoint on the application's existing Fastify listener. */
export function graphqlPlugin(input: GraphqlPluginSettings): Plugin {
  const settings = capture(input);
  // These optional transports are enabled only after their independent runtime gates pass.
  if (settings.subscriptions) throw failure();
  const readiness = new WeakMap<object, () => boolean>();
  const instances = new WeakMap<PluginContext, { close(): Promise<void> }>();
  const plugin: ComposablePlugin = {
    id: 'graphql',
    version: '0.1.0',
    capabilities: new Set(['graphql']),
    dependencies: ['api', 'graphql-authority', 'graphql-observation'],
    [SUPPORT_PLUGINS]: [authority, observations],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      if (!context.options.http) throw failure();
      if (settings.security.developerIDE && context.options.service.environment === 'production')
        throw failure();
      const auth = context.require<AuthService | undefined>(AUTHORITY);
      const observers = context.require<Observers>(OBSERVERS);
      if (
        (settings.security.auth.required ||
          settings.security.introspection === 'authenticated' ||
          settings.security.developerIDE) &&
        !auth
      )
        throw failure();
      if (
        settings.security.auth.required &&
        settings.security.auth.assurance !== undefined &&
        (
          auth as (AuthService & { hasAssurancePolicy?(): boolean }) | undefined
        )?.hasAssurancePolicy?.() !== true
      )
        throw failure();
      const schema = compileSchema(settings),
        server = context.require<ManagedApiServer>(COMPONENTS.api).native(),
        owner = context.require<AbortSignal>(APPLICATION_SIGNAL),
        ready = readiness.get(context.options);
      if (!ready) throw failure();
      const scopes = new WeakMap<object, Operation>(),
        active = new Set<Operation>();
      const counters = {
        operations: 0,
        rejected: 0,
        activeOperations: 0,
        activeSubscriptions: 0,
        loaderBatches: 0,
      };
      let closed = false,
        loaded = false,
        closing: Promise<void> | undefined;
      const close = () =>
        (closing ??= (async () => {
          closed = true;
          try {
            await within(() => Promise.all([...active].map((scope) => scope.completion)), {
              timeoutMs: settings.security.limits.maxOperationMs,
            });
          } catch {
            for (const scope of active) scope.abort();
          }
        })());
      instances.set(context, { close });
      const ownership = Symbol('graphql.route.owner');
      server.addHook('onRoute', (options) => {
        if (
          (options.url === settings.path || options.url.startsWith(settings.path + '/')) &&
          (options.config as Record<symbol, unknown> | undefined)?.[ownership] !== true
        )
          throw failure();
      });
      if (
        ['GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].some((method) =>
          server.hasRoute({ method: method as 'GET', url: settings.path }),
        )
      )
        throw failure();
      server.register(async (child) => {
        const observed = new WeakMap<FastifyRequest, Observation>();
        const metered = new WeakMap<FastifyRequest, RequestUsage>();
        const requestBytes = new WeakMap<FastifyRequest, number>();
        const traced = new WeakSet<FastifyRequest>();
        function inbound<T>(request: FastifyRequest, work: () => T | Promise<T>): T | Promise<T> {
          if (request.routeOptions.url !== settings.path || traced.has(request)) return work();
          traced.add(request);
          return traceRequest(observers, request.method, settings.path, request.headers, work);
        }
        child.addHook('onRequest', async (request, reply) => {
          if (request.routeOptions.url !== settings.path) return;
          const observation = new Observation(observers);
          observed.set(request, observation);
          reply.raw.once('close', () => {
            if (!reply.raw.writableEnded) {
              observation.finish(499);
              metered.get(request)?.finish(499);
            }
          });
        });
        child.addHook('onSend', async (request, _reply, payload) => {
          metered.get(request)?.response(payload);
          return payload;
        });
        child.addHook('onResponse', async (request, reply) => {
          observed.get(request)?.finish(reply.statusCode);
          metered.get(request)?.finish(reply.statusCode);
        });
        const { default: mercurius } = await import('mercurius');
        child.removeContentTypeParser('application/json');
        child.addContentTypeParser(
          'application/json',
          { parseAs: 'buffer' },
          (request, body, done) => {
            try {
              requestBytes.set(request, (body as Buffer).length);
              done(
                null,
                JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body as Buffer)),
              );
            } catch {
              done(failure('EK_GQL_VALIDATION'));
            }
          },
        );
        await child.register(mercurius, {
          schema,
          routes: false,
          cache: false,
          jit: 0,
          graphiql: false,
          allowBatchedQueries: false,
          errorFormatter(result, engineContext) {
            return {
              // Late upstream error formatting must preserve the admitted timeout response.
              statusCode: scopes.get(engineContext)?.controller.signal.aborted ? 504 : 200,
              response: {
                data: result.data ?? null,
                errors: result.errors.map((error) => {
                  const code =
                    typeof error.extensions?.code === 'string' &&
                    ['EK_GQL_FORBIDDEN', 'EK_GQL_TIMEOUT', 'EK_GQL_COMPLEXITY'].includes(
                      error.extensions.code,
                    )
                      ? (error.extensions.code as 'EK_GQL_FORBIDDEN')
                      : 'EK_GQL_EXECUTION';
                  return {
                    message: failure(code).message,
                    ...(error.path ? { path: error.path } : {}),
                    extensions: { code },
                  };
                }),
              },
            };
          },
        });
        installLoaders(child, settings, scopes, () => {
          counters.loaderBatches++;
        });
        protectFields(child.graphql.schema, settings, scopes);
        installMetadata();
        child.graphql.addHook(
          'preExecution',
          (currentSchema, document, engineContext: object, variables: Record<string, unknown>) => {
            const scope = scopes.get(engineContext);
            if (!scope) throw failure('EK_GQL_FORBIDDEN');
            scope.check();
            assertMetadata();
            const estimate = budget(
              currentSchema,
              document,
              variables,
              scope.context,
              settings,
              methods.get(scope) ?? 'POST',
              () => authorizeMetadata(engineContext),
            );
            scope.observation?.budget(estimate.operation, estimate.complexity);
          },
        );
        child.setErrorHandler((error, request, reply) => {
          if (request.routeOptions.url === settings.path) counters.rejected++;
          observed
            .get(request)
            ?.reject(
              (error as { code?: string }).code === 'FST_ERR_CTP_BODY_TOO_LARGE'
                ? failure('EK_GQL_INPUT_LIMIT')
                : error,
            );
          return inbound(request, () =>
            rejected(
              reply,
              (error as { code?: string }).code === 'FST_ERR_CTP_BODY_TOO_LARGE'
                ? failure('EK_GQL_INPUT_LIMIT')
                : error,
              settings.security.limits.maxResultBytes,
            ),
          );
        });
        const methods = new WeakMap<Operation, string>();
        if (settings.security.developerIDE)
          await registerIde(child, settings.path, ownership, async (request) => {
            if (closed || !ready() || active.size >= 128) throw failure('EK_GQL_EXECUTION');
            const scope = new Operation({ requestId: request.id }, settings.security.limits, owner);
            active.add(scope);
            void scope.completion.then(() => active.delete(scope));
            try {
              if (!auth) throw failure('EK_GQL_AUTH');
              const identity = await scope.run(() =>
                auth.verifyBearer(request.headers.authorization, {
                  signal: scope.controller.signal,
                  timeoutMs: settings.security.limits.maxOperationMs,
                }),
              );
              auth.tenantFrom(identity);
              if (settings.security.auth.required) {
                for (const name of settings.security.auth.scopes ?? [])
                  auth.requireScope(identity, name);
                if (settings.security.auth.assurance)
                  auth.requireAssurance(identity, settings.security.auth.assurance);
              }
              if (settings.security.introspection === 'authenticated')
                auth.requireScope(identity, settings.security.introspectionScope!);
              scope.check();
            } catch {
              scope.check();
              throw failure('EK_GQL_AUTH');
            } finally {
              scope.end();
            }
          });
        const handler = async (request: FastifyRequest, reply: FastifyReply) => {
          let scope: Operation | undefined;
          let detach = () => {};
          try {
            if (closed || !ready() || active.size >= 128) throw failure('EK_GQL_EXECUTION');
            counters.operations++;
            if (request.headers.cookie || request.headers['sec-fetch-site'] === 'cross-site')
              throw failure('EK_GQL_FORBIDDEN');
            if (request.headers.origin) {
              const origin = new URL(request.headers.origin);
              if (origin.origin !== `${request.protocol}://${request.host}`)
                throw failure('EK_GQL_FORBIDDEN');
            }
            if (
              request.method === 'POST' &&
              !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(
                request.headers['content-type'] ?? '',
              )
            )
              throw failure('EK_GQL_VALIDATION');
            const body = record(
              request.method === 'GET'
                ? { ...(request.query as Record<string, unknown>) }
                : request.body,
              ['query', 'variables', 'operationName'],
            );
            if (
              typeof body.query !== 'string' ||
              !body.query.trim() ||
              toUSVString(body.query) !== body.query ||
              (body.operationName !== undefined &&
                (typeof body.operationName !== 'string' ||
                  !/^[_A-Za-z][_0-9A-Za-z]*$/.test(body.operationName)))
            )
              throw failure('EK_GQL_VALIDATION');
            if (Buffer.byteLength(body.query) > settings.security.limits.maxDocumentBytes)
              throw failure('EK_GQL_INPUT_LIMIT');
            let variables = body.variables;
            if (request.method === 'GET' && typeof variables === 'string') {
              if (Buffer.byteLength(variables) > settings.security.limits.maxVariablesBytes)
                throw failure('EK_GQL_INPUT_LIMIT');
              variables = JSON.parse(variables);
            }
            if (
              variables !== undefined &&
              (variables === null || typeof variables !== 'object' || Array.isArray(variables))
            )
              throw failure('EK_GQL_VALIDATION');
            if (
              variables !== undefined &&
              Buffer.byteLength(JSON.stringify(variables)) >
                settings.security.limits.maxVariablesBytes
            )
              throw failure('EK_GQL_INPUT_LIMIT');
            const metadata: Omit<GraphqlRequestContext, 'signal'> = {
              requestId: request.id,
              ...(body.operationName === undefined
                ? {}
                : { operationName: body.operationName as string }),
            };
            scope = new Operation(metadata, settings.security.limits, owner, observed.get(request));
            const current = scope;
            const disconnected = () => {
              if (!reply.raw.writableEnded) current.abort();
            };
            request.raw.once('aborted', disconnected);
            reply.raw.once('close', disconnected);
            detach = () => {
              request.raw.off('aborted', disconnected);
              reply.raw.off('close', disconnected);
            };
            active.add(current);
            counters.activeOperations++;
            void current.completion.then(() => {
              active.delete(current);
              counters.activeOperations--;
            });
            let identity, tenant;
            if (settings.security.auth.required || request.headers.authorization !== undefined) {
              if (!auth) throw failure('EK_GQL_AUTH');
              try {
                identity = await current.run(() =>
                  auth.verifyBearer(request.headers.authorization, {
                    signal: current.controller.signal,
                    timeoutMs: settings.security.limits.maxOperationMs,
                  }),
                );
                if (settings.security.auth.required) {
                  for (const name of settings.security.auth.scopes ?? [])
                    auth.requireScope(identity, name);
                  if (settings.security.auth.assurance)
                    auth.requireAssurance(identity, settings.security.auth.assurance);
                }
                tenant = auth.tenantFrom(identity);
              } catch {
                current.check();
                throw failure('EK_GQL_AUTH');
              }
            }
            // Only locally verified authentication enters the immutable resolver context.
            const authenticated = Object.freeze({
              ...current.context,
              ...(identity ? { identity } : {}),
              ...(tenant ? { auth: tenant } : {}),
            });
            Object.defineProperty(current, 'context', { value: authenticated });
            const usage = new RequestUsage(
              observers,
              current,
              tenant,
              request.id,
              request.method,
              settings.path,
              requestBytes.get(request) ?? 0,
            );
            metered.set(request, usage);
            return await usage.http(async () => {
              const engineContext = {};
              scopes.set(engineContext, current);
              ownMetadata(engineContext, {
                scope: current,
                settings,
                authorizeIntrospection() {
                  current.check();
                  if (
                    settings.security.introspection !== 'authenticated' ||
                    !authenticated.identity ||
                    !auth
                  )
                    throw failure('EK_GQL_FORBIDDEN');
                  try {
                    auth.requireScope(
                      authenticated.identity,
                      settings.security.introspectionScope!,
                    );
                  } catch {
                    throw failure('EK_GQL_FORBIDDEN');
                  }
                },
              });
              methods.set(current, request.method);
              try {
                // Use the upstream parser before Mercurius to exclude its JSON-encoded AST fallback.
                let document;
                try {
                  document = parse(body.query as string, {
                    maxTokens: settings.security.limits.maxDocumentBytes,
                  });
                } catch {
                  throw failure('EK_GQL_VALIDATION');
                }
                const result = await current.run(() =>
                  usage.operation(
                    getOperationAST(document, body.operationName as string | undefined)?.operation,
                    () =>
                      traceOperation(
                        observers,
                        getOperationAST(document, body.operationName as string | undefined)
                          ?.operation,
                        () =>
                          reply.graphql(
                            document,
                            engineContext,
                            variables as Record<string, unknown> | undefined,
                            body.operationName as string | undefined,
                          ),
                      ),
                  ),
                );
                current.check();
                const encoded = encodeResult(result, settings.security.limits.maxResultBytes);
                current.check();
                if (result.errors?.length) {
                  counters.rejected++;
                  const code = result.errors[0]?.extensions?.code;
                  current.observation?.reject(
                    failure(
                      typeof code === 'string' &&
                        ['EK_GQL_FORBIDDEN', 'EK_GQL_TIMEOUT', 'EK_GQL_COMPLEXITY'].includes(code)
                        ? (code as 'EK_GQL_FORBIDDEN')
                        : 'EK_GQL_EXECUTION',
                    ),
                  );
                  usage.reject(
                    failure(
                      typeof code === 'string' &&
                        ['EK_GQL_FORBIDDEN', 'EK_GQL_TIMEOUT', 'EK_GQL_COMPLEXITY'].includes(code)
                        ? (code as 'EK_GQL_FORBIDDEN')
                        : 'EK_GQL_EXECUTION',
                    ),
                  );
                }
                current.end();
                return reply.type('application/json').send(encoded);
              } finally {
                detach();
              }
            });
          } catch (error) {
            counters.rejected++;
            observed.get(request)?.reject(error);
            metered.get(request)?.reject(error);
            scope?.end();
            return rejected(reply, error, settings.security.limits.maxResultBytes);
          } finally {
            detach();
            scope?.end();
          }
        };
        for (const method of settings.security.allowGetQueries
          ? (['POST', 'GET'] as const)
          : (['POST'] as const))
          child.route({
            method,
            url: settings.path,
            config: { [ownership]: true },
            bodyLimit: Math.min(
              Number.MAX_SAFE_INTEGER,
              settings.security.limits.maxDocumentBytes * 6 +
                settings.security.limits.maxVariablesBytes * 6 +
                4096,
            ),
            handler: (request, reply) => inbound(request, () => handler(request, reply)),
          });
        loaded = true;
      });
      const service: GraphqlService = Object.freeze({
        stats: () => Object.freeze({ ...counters }),
        health: () =>
          Object.freeze({
            ready: loaded && !closed && ready(),
            schemaLoaded: loaded,
            subscriptionsReady: false,
          }),
        schemaSdl: () => settings.schema,
      });
      context.provide(GRAPHQL_CAPABILITY, service);
    },
    async [DRAIN_PLUGIN](context) {
      await instances.get(context)?.close();
    },
    async close(context) {
      await instances.get(context)?.close();
    },
  };
  return plugin;
}
