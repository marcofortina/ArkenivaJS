// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { request } from 'node:https';
import { TLSSocket } from 'node:tls';
import { timingSafeEqual } from 'node:crypto';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import csrfProtection from '@fastify/csrf-protection';
import { Tokens } from '@fastify/csrf';
import helmet from '@fastify/helmet';
import { createApplication } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';
import { securityHttpPlugin, SECURITY_HTTP_CAPABILITY } from '@arkenivajs/security-http';

export const csrfCookieName = '__Host-arkeniva-csrf';
const namespace = 'arkenivajs.security-http.csrf.v1';
const lifetime = 900000;
const domains = Object.freeze({
  nativeKey: 'arkenivajs.security-http.native-key.v1',
  owner: 'arkenivajs.security-http.owner.v1',
  state: 'arkenivajs.security-http.state.v1',
});

function rejected() {
  const error = new Error('The owned CSRF request was rejected');
  error.code = 'EK_HTTP_CSRF';
  error.statusCode = 403;
  return error;
}

function tokenParts(value) {
  if (typeof value !== 'string' || value.length > 384) throw rejected();
  const parts = value.split('.');
  if (
    parts.length !== 3 ||
    parts[0] !== 'v1' ||
    !/^[A-Za-z0-9_-]{43}$/.test(parts[1]) ||
    Buffer.from(parts[1], 'base64url').toString('base64url') !== parts[1] ||
    !/^[A-Za-z0-9_-]{1,256}$/.test(parts[2])
  )
    throw rejected();
  return { nonce: parts[1], native: parts[2] };
}

function browserOrigin(headers) {
  try {
    const value = headers.origin ?? headers.referer;
    if (typeof value !== 'string' || value.length > 2048) throw rejected();
    const url = new URL(value);
    if (url.username || url.password || url.hash || !['http:', 'https:'].includes(url.protocol))
      throw rejected();
    if (headers.origin !== undefined && value !== url.origin) throw rejected();
    return url.origin;
  } catch {
    throw rejected();
  }
}

function digestValue(value) {
  if (typeof value !== 'string' || value.length < 32 || !/^[\x21-\x7e]{32,1024}$/.test(value))
    throw rejected();
  return value;
}

/** Count only fixed provider boundaries; every decision still delegates to the real fixture. */
export function countedCsrfSettings(settings) {
  const counts = {
    sessionResolve: 0,
    authorityRequire: 0,
    nativeKeyDigest: 0,
    ownerDigest: 0,
    stateDigest: 0,
    storeRead: 0,
    storeCompareAndSet: 0,
  };
  return {
    settings: {
      ...settings,
      csrfStore: {
        ...settings.csrfStore,
        store: {
          ...settings.csrfStore.store,
          async read(...args) {
            counts.storeRead++;
            return settings.csrfStore.store.read(...args);
          },
          async compareAndSet(...args) {
            counts.storeCompareAndSet++;
            return settings.csrfStore.store.compareAndSet(...args);
          },
        },
      },
      csrfHmac: {
        ...settings.csrfHmac,
        async digest(domain, ...args) {
          const name = Object.keys(domains).find((key) => domains[key] === domain);
          if (!name) throw rejected();
          counts[name + 'Digest']++;
          return settings.csrfHmac.digest(domain, ...args);
        },
      },
      authority: {
        ...settings.authority,
        async require(...args) {
          counts.authorityRequire++;
          return settings.authority.require(...args);
        },
      },
      cookieSession: {
        ...settings.cookieSession,
        async resolve(...args) {
          counts.sessionResolve++;
          return settings.cookieSession.resolve(...args);
        },
      },
    },
    snapshot: () => ({ ...counts }),
    reset() {
      for (const name of Object.keys(counts)) counts[name] = 0;
    },
  };
}

/** The upstream baseline composes the same trusted providers; it does not implement an issuer. */
export async function nativeCsrf(settings, tls) {
  assert.equal(settings.policy.csrfEnabled, true);
  assert.deepEqual(settings.cookieRoutes, [{ method: 'POST', path: '/protected' }]);
  const root = Buffer.from(
    digestValue(await settings.csrfHmac.digest(domains.nativeKey, [], settings.csrfKeyRef)),
    'utf8',
  );
  let server;
  const state = { effects: 0 };
  try {
    server = Fastify({
      logger: false,
      maxParamLength: 256,
      https: {
        cert: await readFile(tls.certificateFile),
        key: await readFile(tls.privateKeyFile),
        minVersion: 'TLSv1.3',
      },
    });
    const options = {
        algorithm: 'sha256',
        saltLength: 16,
        secretLength: 32,
        validity: lifetime,
        userInfo: true,
        hmacKey: root,
      },
      tokens = Tokens(options),
      bindings = new WeakMap();
    server.register(cookie);
    server.register(csrfProtection, {
      cookieKey: csrfCookieName,
      cookieOpts: { path: '/', secure: true, httpOnly: true, sameSite: 'strict' },
      csrfOpts: options,
      getToken: (req) => tokenParts(req.headers['x-csrf-token']).native,
      getUserInfo: (req) => bindings.get(req) ?? '',
    });
    server.register(helmet, { global: false });
    server.addHook('onSend', async (_req, reply, payload) => {
      await reply.helmet({
        contentSecurityPolicy: {
          useDefaults: false,
          directives: {
            ...settings.policy.contentSecurityPolicy,
            'frame-ancestors': [...settings.policy.frameAncestors],
          },
        },
        hsts: {
          maxAge: settings.policy.hstsMaxAgeSeconds,
          includeSubDomains: false,
          preload: false,
        },
        referrerPolicy: { policy: 'no-referrer' },
        xContentTypeOptions: true,
        xFrameOptions: false,
      });
      return payload;
    });
    server.setErrorHandler((error, _req, reply) => {
      reply.code(error.statusCode === 403 ? 403 : 500).send({ rejected: true });
    });
    server.after((error) => {
      if (error) throw error;
      server.addHook('onRequest', (req, reply, done) => {
        if (req.method !== 'POST' || req.routeOptions.url !== '/protected') return done();
        void (async () => {
          if (!(req.raw.socket instanceof TLSSocket) || !req.raw.socket.encrypted) throw rejected();
          const parts = tokenParts(req.headers['x-csrf-token']);
          if (req.cookies[csrfCookieName] !== parts.nonce) throw rejected();
          if (!settings.allowedOrigins.includes(browserOrigin(req.headers))) throw rejected();
          const context = Object.freeze({
              method: req.method,
              route: '/protected',
              cookies: Object.freeze({ ...req.cookies }),
              secure: true,
            }),
            session = await settings.cookieSession.resolve(context),
            identity = await settings.authority.require('security-http.verify', undefined, {
              sessionId: session.sessionId,
              request: context,
            });
          assert.equal(typeof identity.issuer, 'string');
          assert.equal(typeof identity.subject, 'string');
          const current = Buffer.from(
            digestValue(await settings.csrfHmac.digest(domains.nativeKey, [], settings.csrfKeyRef)),
            'utf8',
          );
          try {
            if (current.length !== root.length || !timingSafeEqual(current, root)) throw rejected();
          } finally {
            current.fill(0);
          }
          const binding = digestValue(
              await settings.csrfHmac.digest(
                domains.owner,
                [
                  identity.issuer,
                  identity.subject,
                  identity.tenant?.tenantId ?? '',
                  session.sessionId,
                ],
                settings.csrfKeyRef,
              ),
            ),
            id = digestValue(
              await settings.csrfHmac.digest(
                domains.state,
                [binding, parts.nonce],
                settings.csrfKeyRef,
              ),
            ),
            stored = await settings.csrfStore.store.read(namespace, id);
          if (
            !stored ||
            Object.keys(stored).some(
              (name) => !['kind', 'binding', 'ownerKey', 'expiresAt', 'version'].includes(name),
            ) ||
            stored.kind !== 'csrf' ||
            stored.binding !== binding ||
            stored.ownerKey !== binding ||
            typeof stored.expiresAt !== 'string' ||
            !Number.isFinite(Date.parse(stored.expiresAt)) ||
            Date.parse(stored.expiresAt) <= Date.now() ||
            Date.parse(stored.expiresAt) > Date.now() + lifetime + 1000 ||
            !tokens.verify(parts.nonce, parts.native, binding)
          )
            throw rejected();
          bindings.set(req, binding);
          server.csrfProtection(req, reply, done);
        })().catch(() => done(rejected()));
      });
    });
    server.post('/protected', async () => {
      state.effects++;
      return { ok: true };
    });
    await server.listen({ host: '127.0.0.1', port: 0 });
    return {
      address: () => 'https://localhost:' + server.server.address().port,
      effects: () => state.effects,
      async close() {
        try {
          await server.close();
        } finally {
          root.fill(0);
        }
      },
    };
  } catch (cause) {
    try {
      await server?.close();
    } finally {
      root.fill(0);
    }
    throw cause;
  }
}

/** The first slice uses telemetry-off framework requests and the existing public CSRF service. */
export async function frameworkCsrf(settings, tls) {
  const state = { effects: 0 },
    app = await createApplication({
      service: { name: 'csrf-comparison-control', version: '1.0.0', environment: 'test' },
      http: {
        host: '127.0.0.1',
        port: 0,
        protocol: 'https',
        tls: {
          certificateFile: tls.certificateFile,
          privateKeyFile: tls.privateKeyFile,
          minVersion: 'TLSv1.3',
        },
      },
      logging: { level: 'silent' },
      plugins: [loggingPlugin(), apiPlugin(), securityHttpPlugin(settings)],
    });
  app.api.get('/token', {
    schema: {
      response: {
        type: 'object',
        properties: { token: { type: 'string' } },
        required: ['token'],
        additionalProperties: false,
      },
    },
    auth: { required: false },
    async handler(context) {
      return {
        token: await app
          .resolve(SECURITY_HTTP_CAPABILITY)
          .csrfToken({ sessionId: context.headers['x-session-hint'] ?? '' }),
      };
    },
  });
  app.api.post('/protected', {
    schema: {
      response: {
        type: 'object',
        properties: { ok: { type: 'boolean' } },
        required: ['ok'],
        additionalProperties: false,
      },
    },
    auth: { required: false },
    handler() {
      state.effects++;
      return { ok: true };
    },
  });
  try {
    await app.start();
    return {
      address: () => 'https://localhost:' + new URL(app.api.address()).port,
      effects: () => state.effects,
      close: () => app.stop(),
    };
  } catch (cause) {
    await app.stop();
    throw cause;
  }
}

/** Credentials remain ephemeral; only callers choose which bounded observations to retain. */
export async function csrfExchange(server, tls, headers, path = '/protected') {
  assert.match(server.address(), /^https:\/\/localhost:[0-9]+$/);
  assert.ok(['/protected', '/token'].includes(path));
  const ca = await readFile(tls.certificateFile);
  return new Promise((resolve, reject) => {
    const req = request(
      server.address() + path,
      {
        method: path === '/token' ? 'GET' : 'POST',
        agent: false,
        ca,
        minVersion: 'TLSv1.3',
        headers,
        timeout: 5000,
      },
      (response) => {
        const chunks = [];
        let bytes = 0;
        const secure = response.socket.authorized === true;
        const protocol = response.socket.getProtocol();
        response.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > 4096)
            response.destroy(new Error('The owned CSRF response exceeded capacity'));
          else chunks.push(chunk);
        });
        response.once('error', reject);
        response.once('end', () => {
          if (!secure || protocol !== 'TLSv1.3')
            return reject(new Error('Unverified CSRF transport'));
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: Buffer.concat(chunks).toString('utf8'),
            tls: { authorized: secure, protocol },
          });
        });
      },
    );
    req.once('timeout', () => req.destroy(new Error('The owned CSRF exchange timed out')));
    req.once('error', reject);
    req.end();
  });
}
