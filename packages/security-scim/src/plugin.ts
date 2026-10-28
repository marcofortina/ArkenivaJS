// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder } from 'node:util';
import { COMPONENTS, APPLICATION_SIGNAL, KitError } from '@arkenivajs/core';
import type { AuthService, ApiServer, Plugin } from '@arkenivajs/core';
import { PREPARE_PLUGIN, DRAIN_PLUGIN, SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { ScimPluginSettings, ScimHttpRequest } from './contracts.js';
import { capture, pluginSettings } from './settings.js';
import { managed } from './service.js';
import { failure } from './validation.js';
import { observations, OBSERVATION } from './observation.js';
import type { Observers } from './observation.js';

export const SCIM_CAPABILITY: unique symbol = Symbol('arkenivajs.security.scim');
const AUTH = Symbol('scim.authentication');
const authentication: SupportPluginFactory = (options) => {
  const owner = options.plugins?.find((plugin) => plugin.capabilities.has('auth'));
  return {
    id: 'scim-authentication',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: owner ? [owner.id] : [],
    init(context) {
      if (!owner) throw failure('EK_AUTH_REQUIRED');
      context.provide<AuthService>(AUTH, context.require<AuthService>(COMPONENTS.auth));
    },
    close() {},
  };
};
/** Register only the owned SCIM route scope; authentication and HTTP listeners retain their existing owners. */
export function scimPlugin(input: ScimPluginSettings): Plugin {
  const selected = pluginSettings(input),
    states = new WeakMap<object, () => boolean>(),
    instances = new WeakMap<object, ReturnType<typeof managed>>();
  const plugin: ComposablePlugin = {
    id: 'security-scim',
    version: '0.1.0',
    capabilities: new Set(['security-scim']),
    dependencies: ['api', 'scim-authentication', 'scim-observation'],
    [SUPPORT_PLUGINS]: [authentication, observations],
    [PREPARE_PLUGIN](context) {
      states.set(context.options, () => context.state() === 'READY');
      return new Map();
    },
    init(context) {
      const ready = states.get(context.options),
        environment = context.options.service.environment;
      if (!ready || (environment !== 'test' && selected.testOnly))
        throw failure('EK_CONFIG_INVALID');
      const auth = context.require<AuthService>(AUTH),
        signal = context.require<AbortSignal>(APPLICATION_SIGNAL),
        settings = Object.freeze({
          ...capture({
            auth,
            authority: selected.authority,
            environment,
            maxPageSize: selected.maxPageSize,
            maxFilterDepth: selected.maxFilterDepth,
          }),
          maxConcurrent: selected.maxConcurrent,
          maxRequestBytes: selected.maxRequestBytes,
          capabilities: selected.capabilities,
        });
      const ports = context.require<Observers>(OBSERVATION);
      const owner = managed(settings, signal, ready, {
        logger: context.logger,
        ...ports,
      });
      owner.service.registerUsers(selected.users);
      owner.service.registerGroups(selected.groups);
      owner.seal();
      instances.set(context, owner);
      const server = context.require<ApiServer>(COMPONENTS.api).native() as FastifyInstance;
      server.register(
        async (scope) => {
          const errorBody = (status: number) => ({
            schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
            status: String(status),
            detail:
              status === 401 || status === 403
                ? 'The provisioning request is not authorized'
                : status === 503
                  ? 'The provisioning backend is unavailable'
                  : 'The provisioning request could not be accepted',
          });
          scope.addHook('onSend', async (request, reply, payload) => {
            if (request.raw.httpVersionMajor === 2) reply.removeHeader('connection');
            return payload;
          });
          scope.removeAllContentTypeParsers();
          scope.addContentTypeParser(
            ['application/scim+json', 'application/json'],
            { parseAs: 'buffer', bodyLimit: selected.maxRequestBytes },
            (_request, body, done) => {
              try {
                done(
                  null,
                  JSON.parse(
                    new TextDecoder('utf-8', { fatal: true }).decode(body as Buffer),
                  ) as unknown,
                );
              } catch {
                done(failure());
              }
            },
          );
          scope.setErrorHandler((error, _request, reply) => {
            const candidate = (error as { statusCode?: unknown }).statusCode,
              status =
                candidate === 413 || candidate === 415
                  ? candidate
                  : error instanceof KitError &&
                      ['EK_AUTH_REQUIRED', 'EK_AUTH_INVALID'].includes(error.code)
                    ? 401
                    : error instanceof KitError && error.code === 'EK_SCIM_UNAUTHORIZED'
                      ? 403
                      : 400;
            reply
              .header('cache-control', 'no-store')
              .type('application/scim+json')
              .code(status)
              .send(errorBody(status));
          });
          scope.setNotFoundHandler((_request, reply) =>
            reply
              .header('cache-control', 'no-store')
              .type('application/scim+json')
              .code(404)
              .send(errorBody(404)),
          );
          const handle = async (request: FastifyRequest, reply: FastifyReply) => {
            const controller = new AbortController(),
              aborted = () => controller.abort(),
              closed = () => {
                if (!reply.raw.writableFinished) controller.abort();
              },
              signal = AbortSignal.any([
                controller.signal,
                context.require<AbortSignal>(APPLICATION_SIGNAL),
              ]);
            request.raw.once('aborted', aborted);
            reply.raw.once('close', closed);
            try {
              const headers: Record<string, string | undefined> = Object.create(null);
              for (const [key, value] of Object.entries(request.headers)) {
                if (key.startsWith(':')) continue;
                if (Array.isArray(value)) throw failure();
                headers[key] = value;
              }
              const result = await owner.http(
                {
                  method: request.method as ScimHttpRequest['method'],
                  path: request.raw.url!.slice('/scim/v2'.length),
                  headers,
                  body: request.body,
                },
                { signal, timeoutMs: 5000 },
              );
              for (const [key, value] of Object.entries(result.headers))
                reply.header(key, key === 'location' ? '/scim/v2' + value : value);
              return reply
                .code(result.status)
                .send(result.status === 204 ? undefined : result.body);
            } catch (error) {
              if (reply.raw.destroyed) return reply;
              const code = error instanceof KitError ? error.code : 'EK_BACKEND_UNAVAILABLE',
                status = ['EK_AUTH_REQUIRED', 'EK_AUTH_INVALID'].includes(code)
                  ? 401
                  : ['EK_AUTH_FORBIDDEN', 'EK_TENANT_UNVERIFIED', 'EK_SCIM_UNAUTHORIZED'].includes(
                        code,
                      )
                    ? 403
                    : code === 'EK_TIMEOUT'
                      ? 504
                      : code === 'EK_SCIM_BAD_REQUEST'
                        ? 400
                        : 503;
              return reply
                .header('cache-control', 'no-store')
                .type('application/scim+json')
                .code(status)
                .send(errorBody(status));
            } finally {
              request.raw.off('aborted', aborted);
              reply.raw.off('close', closed);
              controller.abort();
            }
          };
          for (const kind of ['Users', 'Groups'])
            for (const url of ['/' + kind, '/' + kind + '/:id'])
              scope.route({
                method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
                url,
                bodyLimit: selected.maxRequestBytes,
                handler: handle,
              });
          for (const url of [
            '/Schemas',
            '/Schemas/:id',
            '/ResourceTypes',
            '/ResourceTypes/:id',
            '/ServiceProviderConfig',
          ])
            scope.get(url, handle);
        },
        { prefix: '/scim/v2' },
      );
      context.provide(SCIM_CAPABILITY, owner.service);
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
