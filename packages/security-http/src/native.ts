// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { TLSSocket } from 'node:tls';
import cookie from '@fastify/cookie';
import csrfProtection from '@fastify/csrf-protection';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import type { HttpSecurityRequest } from './contracts.js';
import type { Settings } from './settings.js';
import type { ProviderTask } from './provider-task.js';
import type { Observers } from './observation.js';
import { observation } from './observation.js';
import { createService, tokenOptions, tokenParts } from './service.js';
import { installNativeHeaders } from './headers.js';
import { failure, origin } from './validation.js';

type Entry = {
  request: HttpSecurityRequest;
  signal: AbortSignal;
  controller: AbortController;
  reply: FastifyReply;
  release(): void;
};
const cookieName = '__Host-arkeniva-csrf';
function browserOrigin(request: FastifyRequest): string {
  try {
    if (request.headers.origin !== undefined) return origin(request.headers.origin);
    const referer = request.headers.referer;
    if (typeof referer !== 'string' || referer.length > 2048) throw failure('EK_HTTP_CSRF');
    const url = new URL(referer);
    if (url.username || url.password || url.hash) throw failure('EK_HTTP_CSRF');
    return origin(url.origin);
  } catch {
    throw failure('EK_HTTP_CSRF');
  }
}
/** One native request context and the prescribed Fastify adapters; no parallel listener or fake request. */
export async function createNative(
  settings: Settings,
  server: FastifyInstance,
  owner: AbortSignal,
  ready: () => boolean,
  test: boolean,
  keyTask: ProviderTask,
  observers: Observers = {},
) {
  const scope = new AsyncLocalStorage<Entry>(),
    entries = new WeakMap<FastifyRequest, Entry>(),
    bindings = new WeakMap<FastifyRequest, string>(),
    observed = observation(observers);
  const managed = await createService(
    settings,
    owner,
    ready,
    () => scope.getStore(),
    (nonce) => {
      const entry = scope.getStore();
      if (!entry) return;
      if (entry.signal.aborted || !ready() || entry.reply.sent) throw failure('EK_ABORTED', true);
      entry.reply.setCookie(cookieName, nonce, {
        path: '/',
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 900,
      });
    },
    keyTask,
    observers,
  );
  try {
    installNativeHeaders(server, managed.currentPolicy);
    server.register(cookie);
    server.register(csrfProtection, {
      cookieKey: cookieName,
      cookieOpts: { path: '/', secure: true, httpOnly: true, sameSite: 'strict' },
      csrfOpts: tokenOptions(managed.nativeKey),
      getToken(request) {
        return tokenParts(request.headers['x-csrf-token']).native;
      },
      getUserInfo(request) {
        return bindings.get(request) ?? '';
      },
    });
    server.after((error) => {
      if (error) throw failure();
      server.addHook('onRequest', (request, reply, done) => {
        try {
          const controller = new AbortController(),
            cookies: Record<string, string> = Object.create(null);
          for (const [name, value] of Object.entries(request.cookies))
            if (typeof value === 'string') cookies[name] = value;
          const address = request.raw.socket.remoteAddress ?? '';
          const secure =
            (request.raw.socket instanceof TLSSocket && request.raw.socket.encrypted) ||
            (settings.permitsProxy(address) && request.headers['x-forwarded-proto'] === 'https') ||
            (test && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(address));
          let released = false;
          const entry: Entry = {
            controller,
            signal: controller.signal,
            reply,
            request: Object.freeze({
              method: request.method,
              route: request.routeOptions.url ?? '',
              cookies: Object.freeze(cookies),
              secure,
            }),
            release() {
              if (released) return;
              released = true;
              request.raw.off('aborted', disconnected);
              reply.raw.off('close', responseClosed);
              entries.delete(request);
              bindings.delete(request);
            },
          };
          const disconnected = () => {
            controller.abort();
            entry.release();
          };
          const responseClosed = () => {
            if (!reply.raw.writableEnded) disconnected();
          };
          request.raw.once('aborted', disconnected);
          reply.raw.once('close', responseClosed);
          entries.set(request, entry);
          scope.run(entry, done);
        } catch {
          done(failure('EK_HTTP_CSRF'));
        }
      });
      server.addHook('onRequest', (request, reply, done) => {
        if (
          !settings.routes.some(
            (route) => route.method === request.method && route.path === request.routeOptions.url,
          )
        ) {
          done();
          return;
        }
        const entry = entries.get(request);
        if (!entry || !entry.request.secure) {
          observed.reject();
          done(failure('EK_HTTP_CSRF'));
          return;
        }
        scope.run(entry, () => {
          let verificationStarted = false;
          const task = Promise.resolve().then(async () => {
            const token = request.headers['x-csrf-token'],
              parsed = tokenParts(token);
            if (request.cookies[cookieName] !== parsed.nonce) throw failure('EK_HTTP_CSRF');
            const suppliedOrigin = browserOrigin(request);
            if (!settings.origins.includes(suppliedOrigin)) throw failure('EK_HTTP_CSRF');
            const sessionId = await managed.resolveSession(entry.request);
            verificationStarted = true;
            return managed.verifyCookie({ sessionId, origin: suppliedOrigin }, token as string);
          });
          void task.then(
            (verified) => {
              if (entry.signal.aborted || !ready()) {
                done(failure('EK_ABORTED'));
                return;
              }
              bindings.set(request, verified.binding);
              try {
                server.csrfProtection(request, reply, done);
              } catch {
                done(failure('EK_HTTP_CSRF'));
              }
            },
            () => {
              if (!verificationStarted) observed.reject();
              done(failure('EK_HTTP_CSRF'));
            },
          );
        });
      });
      server.addHook('onResponse', async (request) => {
        entries.get(request)?.release();
      });
      server.addHook('onReady', async () => {
        if (
          settings.routes.some(
            (route) => !server.hasRoute({ method: route.method, url: route.path }),
          )
        )
          throw failure();
      });
    });
    return managed;
  } catch {
    await managed.close();
    throw failure();
  }
}
