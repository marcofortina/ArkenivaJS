// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder, toUSVString } from 'node:util';
import { parse } from 'graphql';
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
import { Operation } from './operation.js';
import { capture, failure, record } from './policy.js';
import { compileSchema } from './schema.js';

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
  if (
    settings.subscriptions ||
    settings.security.developerIDE ||
    settings.security.introspection !== 'disabled'
  )
    throw failure();
  const readiness = new WeakMap<object, () => boolean>();
  const instances = new WeakMap<PluginContext, { close(): Promise<void> }>();
  const plugin: ComposablePlugin = {
    id: 'graphql',
    version: '0.1.0',
    capabilities: new Set(['graphql']),
    dependencies: ['api', 'graphql-authority'],
    [SUPPORT_PLUGINS]: [authority],
    [PREPARE_PLUGIN](context) {
      readiness.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    async init(context) {
      if (!context.options.http) throw failure();
      const auth = context.require<AuthService | undefined>(AUTHORITY);
      if (settings.security.auth.required && !auth) throw failure();
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
        const { default: mercurius } = await import('mercurius');
        child.removeContentTypeParser('application/json');
        child.addContentTypeParser(
          'application/json',
          { parseAs: 'buffer' },
          (_request, body, done) => {
            try {
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
          errorFormatter(result) {
            return {
              statusCode: 200,
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
        child.graphql.addHook(
          'preExecution',
          (currentSchema, document, engineContext: object, variables: Record<string, unknown>) => {
            const scope = scopes.get(engineContext);
            if (!scope) throw failure('EK_GQL_FORBIDDEN');
            scope.check();
            budget(
              currentSchema,
              document,
              variables,
              scope.context,
              settings,
              methods.get(scope) ?? 'POST',
            );
          },
        );
        child.setErrorHandler((error, _request, reply) => {
          counters.rejected++;
          return rejected(
            reply,
            (error as { code?: string }).code === 'FST_ERR_CTP_BODY_TOO_LARGE'
              ? failure('EK_GQL_INPUT_LIMIT')
              : error,
            settings.security.limits.maxResultBytes,
          );
        });
        const methods = new WeakMap<Operation, string>();
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
            scope = new Operation(metadata, settings.security.limits, owner);
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
            const engineContext = {};
            scopes.set(engineContext, current);
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
                reply.graphql(
                  document,
                  engineContext,
                  variables as Record<string, unknown> | undefined,
                  body.operationName as string | undefined,
                ),
              );
              current.check();
              const encoded = JSON.stringify(result);
              if (Buffer.byteLength(encoded) > settings.security.limits.maxResultBytes)
                throw failure('EK_GQL_RESPONSE_LIMIT');
              if (result.errors?.length) counters.rejected++;
              return reply.type('application/json').send(encoded);
            } finally {
              detach();
            }
          } catch (error) {
            counters.rejected++;
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
            handler,
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
