// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import Fastify from 'fastify';
import mercurius from 'mercurius';
import type { MercuriusContext } from 'mercurius';
import { createClient } from 'graphql-ws';
import type { Client } from 'graphql-ws';
import WebSocket from 'ws';
import { generateKeyPair, jwtVerify, SignJWT } from 'jose';
import { tlsFiles } from '../fixture.js';
import { OwnedContexts } from '../../dist/contexts.js';

/** Engine compatibility probes do not activate the framework's subscription transport. */
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

interface Session {
  readonly token: string;
  readonly subject: string;
  readonly tenant: string;
}

async function nativeFixture() {
  const tls = await tlsFiles();
  const pair = await generateKeyPair('ES256');
  const server = Fastify({
    logger: false,
    https: {
      key: await readFile(tls.tls.privateKeyFile),
      cert: await readFile(tls.tls.certificateFile),
    },
  });
  const sessions = new OwnedContexts<Session>();
  const retiring = new WeakMap<Session, () => void>();
  const revoked = new Set<string>();
  const started = new Map<string, ReturnType<typeof deferred<void>>>();
  const ended = new Map<string, ReturnType<typeof deferred<void>>>();
  const parsingContexts: object[] = [];
  const resolverContexts: object[] = [];
  let verified = 0;
  const verify = async (token: string): Promise<Session> => {
    const result = await jwtVerify(token, pair.publicKey, {
      algorithms: ['ES256'],
      issuer: 'https://issuer.example.test',
      audience: 'native-subscription-probe',
      requiredClaims: ['sub', 'tenant', 'exp', 'jti'],
    });
    assert.equal(typeof result.payload.sub, 'string');
    assert.ok(['tenant-a', 'tenant-b'].includes(String(result.payload.tenant)));
    assert.ok(!revoked.has(String(result.payload.jti)));
    verified++;
    return Object.freeze({
      token,
      subject: result.payload.sub!,
      tenant: String(result.payload.tenant),
    });
  };
  const revalidate = async (context: object) => {
    const session = sessions.get(context);
    assert.ok(session, 'Context copies must retain a server-owned session');
    const fresh = await verify(session.token);
    assert.equal(fresh.subject, session.subject);
    assert.equal(fresh.tenant, session.tenant);
    return session;
  };
  try {
    await server.register(mercurius, {
      schema: `
        type Notice { id: ID!, text: String! }
        type Query { heartbeat: Boolean! }
        type Subscription { notice(tenantHint: String): Notice! }
      `,
      resolvers: {
        Query: { heartbeat: () => true },
        Subscription: {
          notice: {
            async subscribe(_parent: unknown, _args: unknown, context: MercuriusContext) {
              resolverContexts.push(context);
              const session = await revalidate(context);
              const stream = await context.pubsub.subscribe(session.tenant);
              started.get(session.tenant)?.resolve();
              return stream;
            },
          },
        },
      },
      subscription: {
        fullWsTransport: false,
        queueHighWaterMark: 2,
        keepAlive: 100,
        verifyClient(info, next) {
          next(info.secure && info.origin === 'https://portal.example.test');
        },
        onDisconnect(context) {
          const session = sessions.get(context);
          if (session) retiring.get(session)?.();
        },
        async onConnect(data: { payload: unknown }) {
          const payload = data.payload as { authorization?: unknown } | undefined;
          if (typeof payload?.authorization !== 'string') return false;
          try {
            const session = await verify(payload.authorization);
            const context = {};
            retiring.set(
              session,
              sessions.bind(context, () => session),
            );
            return context;
          } catch {
            return false;
          }
        },
      },
      graphiql: false,
      jit: 0,
      allowBatchedQueries: false,
    });
    server.graphql.addHook<MercuriusContext>(
      'preSubscriptionParsing',
      (_schema, _source, context) => {
        parsingContexts.push(context);
      },
    );
    server.graphql.addHook<MercuriusContext>(
      'preSubscriptionExecution',
      async (_s, _d, context) => {
        await revalidate(context);
      },
    );
    server.graphql.addHook(
      'onSubscriptionResolution',
      async (_execution, context: MercuriusContext) => {
        await revalidate(context);
      },
    );
    server.graphql.addHook<MercuriusContext>('onSubscriptionEnd', (context) => {
      const session = sessions.get(context);
      assert.ok(session);
      ended.get(session.tenant)?.resolve();
    });
    await server.listen({ host: '127.0.0.1', port: 0 });
    const address = server.server.address();
    assert.ok(address && typeof address === 'object');
    const clients = new Set<Client>();
    return {
      server,
      started,
      ended,
      parsingContexts,
      resolverContexts,
      verified: () => verified,
      revoked,
      async client(
        tenant: string,
        options: { invalid?: boolean; expired?: boolean; origin?: string } = {},
      ) {
        class TrustedSocket extends WebSocket {
          constructor(url: string, protocols?: string | string[]) {
            super(url, protocols, {
              ca: tls.ca,
              origin: options.origin ?? 'https://portal.example.test',
            });
          }
        }
        const signer = options.invalid ? await generateKeyPair('ES256') : pair;
        const token = await new SignJWT({ tenant })
          .setProtectedHeader({ alg: 'ES256' })
          .setIssuer('https://issuer.example.test')
          .setAudience('native-subscription-probe')
          .setSubject('subject-' + tenant)
          .setJti('session-' + tenant)
          .setIssuedAt()
          .setExpirationTime(options.expired ? 1 : '2m')
          .sign(signer.privateKey);
        const connected = deferred<void>();
        const pong = deferred<void>();
        const closed = deferred<void>();
        void connected.promise.catch(() => undefined);
        const client = createClient({
          url: `wss://127.0.0.1:${address.port}/graphql`,
          webSocketImpl: TrustedSocket,
          connectionParams: { authorization: token },
          retryAttempts: 0,
          keepAlive: 100,
          on: {
            connected(socket) {
              assert.equal((socket as WebSocket).protocol, 'graphql-transport-ws');
              connected.resolve();
            },
            pong: () => pong.resolve(),
            closed: () => closed.resolve(),
            error: (error) => connected.reject(error),
          },
        });
        clients.add(client);
        return { client, connected, pong, closed };
      },
      async close() {
        await Promise.all([...clients].map((client) => client.dispose()));
        await server.close();
        await tls.close();
      },
    };
  } catch (error) {
    await server.close();
    await tls.close();
    throw error;
  }
}

test(
  'Pinned Mercurius and graphql-ws interoperate over verified WSS with signed tenant routing and clean unsubscribe',
  { timeout: 10000 },
  async () => {
    const fixture = await nativeFixture();
    const stops: (() => void)[] = [];
    try {
      const a = await fixture.client('tenant-a');
      const b = await fixture.client('tenant-b');
      const receivedA = deferred<unknown>();
      const receivedB = deferred<unknown>();
      for (const [tenant, connection, received] of [
        ['tenant-a', a, receivedA],
        ['tenant-b', b, receivedB],
      ] as const) {
        fixture.started.set(tenant, deferred<void>());
        fixture.ended.set(tenant, deferred<void>());
        stops.push(
          connection.client.subscribe(
            {
              query:
                'subscription Notice($tenant: String!) { notice(tenantHint: $tenant) { id text } }',
              variables: { tenant: tenant === 'tenant-a' ? 'tenant-b' : 'tenant-a' },
              operationName: 'Notice',
            },
            {
              next: (value) => received.resolve(value),
              error: received.reject,
              complete() {},
            },
          ),
        );
      }
      await Promise.all([
        a.connected.promise,
        b.connected.promise,
        ...[...fixture.started.values()].map((value) => value.promise),
      ]);
      assert.equal(fixture.parsingContexts.length, 2);
      assert.equal(fixture.resolverContexts.length, 2);
      assert.notEqual(
        fixture.parsingContexts[0],
        fixture.resolverContexts[0],
        'The native engine copies context before invoking subscribe',
      );
      await fixture.server.graphql.pubsub.publish({
        topic: 'tenant-a',
        payload: { notice: { id: 'a-1', text: 'alpha' } },
      });
      await fixture.server.graphql.pubsub.publish({
        topic: 'tenant-b',
        payload: { notice: { id: 'b-1', text: 'beta' } },
      });
      assert.deepEqual(await receivedA.promise, { data: { notice: { id: 'a-1', text: 'alpha' } } });
      assert.deepEqual(await receivedB.promise, { data: { notice: { id: 'b-1', text: 'beta' } } });
      await Promise.all([a.pong.promise, b.pong.promise]);
      assert.ok(fixture.verified() >= 8);
      for (const stop of stops.splice(0)) stop();
      await Promise.all([...fixture.ended.values()].map((value) => value.promise));
    } finally {
      for (const stop of stops) stop();
      await fixture.close();
    }
  },
);

test(
  'Native subscription establishment rejects a bearer signed by an untrusted key before source allocation',
  { timeout: 10000 },
  async () => {
    const fixture = await nativeFixture();
    try {
      const connection = await fixture.client('tenant-a', { invalid: true });
      const failed = deferred<unknown>();
      const stop = connection.client.subscribe(
        { query: 'subscription { notice { id } }' },
        {
          next: failed.reject,
          error: failed.resolve,
          complete: () => failed.reject(new Error('Untrusted subscription unexpectedly completed')),
        },
      );
      try {
        await failed.promise;
        assert.equal(fixture.verified(), 0);
        assert.equal(fixture.resolverContexts.length, 0);
      } finally {
        stop();
      }
    } finally {
      await fixture.close();
    }
  },
);

test(
  'Native WSS rejects disallowed browser origins and expired signed credentials before subscription allocation',
  { timeout: 10000 },
  async () => {
    const fixture = await nativeFixture();
    try {
      for (const options of [{ origin: 'https://untrusted.example.test' }, { expired: true }]) {
        const connection = await fixture.client('tenant-a', options);
        const failed = deferred<unknown>();
        const stop = connection.client.subscribe(
          { query: 'subscription { notice { id } }' },
          {
            next: failed.reject,
            error: failed.resolve,
            complete: () => failed.reject(new Error('Denied subscription unexpectedly completed')),
          },
        );
        try {
          await failed.promise;
          assert.equal(fixture.verified(), 0);
          assert.equal(fixture.resolverContexts.length, 0);
        } finally {
          stop();
        }
      }
    } finally {
      await fixture.close();
    }
  },
);

test(
  'Revalidation through the native delivery hook prevents an established subscription from receiving after revocation',
  { timeout: 10000 },
  async () => {
    const fixture = await nativeFixture();
    let stop: (() => void) | undefined;
    try {
      const ready = deferred<void>();
      fixture.started.set('tenant-a', ready);
      const connection = await fixture.client('tenant-a');
      const first = deferred<unknown>();
      const received: unknown[] = [];
      stop = connection.client.subscribe(
        { query: 'subscription { notice { id } }' },
        {
          next(value) {
            received.push(value);
            first.resolve(value);
          },
          error: first.reject,
          complete() {},
        },
      );
      await ready.promise;
      await fixture.server.graphql.pubsub.publish({
        topic: 'tenant-a',
        payload: { notice: { id: 'before' } },
      });
      assert.deepEqual(await first.promise, { data: { notice: { id: 'before' } } });
      fixture.revoked.add('session-tenant-a');
      await fixture.server.graphql.pubsub.publish({
        topic: 'tenant-a',
        payload: { notice: { id: 'after' } },
      });
      await connection.closed.promise;
      assert.deepEqual(received, [{ data: { notice: { id: 'before' } } }]);
    } finally {
      stop?.();
      await fixture.close();
    }
  },
);
