// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { setImmediate, setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';
import { COMPONENTS } from '@arkenivajs/core';
import type { ManagedAuthService } from '@arkenivajs/security';
import type { GraphqlPluginSettings } from '../../dist/index.js';
import { fixture, send, tlsFiles } from '../fixture.js';

for (const transport of ['HTTPS', 'WSS'] as const)
  test(
    `Public ${transport} rejects a tenant policy that closes its actual verifier while returning approval`,
    { timeout: 10000 },
    async () => {
      const tls = await tlsFiles();
      let f: Awaited<ReturnType<typeof fixture>> | undefined,
        authority: ManagedAuthService | undefined,
        closing: Promise<void> | undefined,
        socket: WebSocket | undefined,
        tenantChecks = 0,
        policies = 0,
        mutations = 0,
        getters = 0,
        allocated = 0;
      const value: GraphqlPluginSettings = {
        schema:
          'type Result { secret: String! } type Query { ping: String! } type Mutation { update: Result! }' +
          (transport === 'WSS' ? ' type Subscription { notice: String! }' : ''),
        resolvers: {
          Query: { ping: () => 'pong' },
          Mutation: {
            update() {
              mutations++;
              return {
                get secret() {
                  getters++;
                  return 'owned-private-retired-policy-result';
                },
              };
            },
          },
          ...(transport === 'WSS'
            ? {
                Subscription: {
                  notice: {
                    subscribe() {
                      allocated++;
                      return (async function* () {
                        yield 'owned-private-retired-policy-event';
                      })();
                    },
                    resolve: (parent: unknown) => parent,
                  },
                },
              }
            : {}),
        },
        security: {
          auth: { required: true, scopes: ['graphql:read'] },
          authorizeField() {
            policies++;
            return true;
          },
          limits: { maxOperationMs: 1000 },
        },
        ...(transport === 'WSS'
          ? {
              subscriptions: {
                enabled: true,
                pubsub: {
                  subscribe() {
                    throw new Error('Retired authentication cannot acquire a source');
                  },
                  async publish() {},
                  async close() {},
                },
                maxConnections: 2,
                maxOperationsPerConnection: 2,
                maxQueuedEventsPerConnection: 4,
                revalidateIntervalMs: 5000,
                allowedOrigins: ['https://portal.example.test'],
              },
            }
          : {}),
      };
      try {
        f = await fixture(value, {
          tls: tls.tls,
          authorizeTenant() {
            tenantChecks++;
            // WSS checks the pinned principal again before admitting the native connection context.
            if (tenantChecks === (transport === 'HTTPS' ? 1 : 2)) {
              assert.ok(authority);
              closing = authority.close();
              void closing.catch(() => undefined);
            }
            return true;
          },
        });
        authority = f.app.resolve<ManagedAuthService>(COMPONENTS.auth);
        const authorization = await f.token();
        if (transport === 'HTTPS') {
          const result = await send(
            f.origin,
            { query: 'mutation { update { secret } }' },
            { headers: { authorization }, ca: tls.ca },
          );
          assert.equal(result.status, 401);
          assert.match(result.body, /EK_GQL_AUTH/);
          assert.doesNotMatch(result.body, /owned-private|EK_RESOURCE_CLOSED|Bearer /);
          assert.equal(tenantChecks, 1);
        } else {
          socket = new WebSocket(
            f.origin.replace('https:', 'wss:') + '/graphql',
            'graphql-transport-ws',
            { ca: tls.ca, origin: 'https://portal.example.test' },
          );
          await once(socket, 'open');
          const messages: string[] = [];
          const refusedAdmission = new Promise<never>((_resolve, reject) => {
            socket!.on('message', (data) => {
              const message = String(data);
              messages.push(message);
              if (/connection_ack|"next"/.test(message))
                reject(new Error('The retired verifier admitted an authenticated WSS connection'));
            });
          });
          const closed = once(socket, 'close');
          socket.send(JSON.stringify({ type: 'connection_init', payload: { authorization } }));
          await Promise.race([
            closed,
            refusedAdmission,
            delay(3000, undefined, { ref: false }).then(() => {
              throw new Error('The retired verifier did not close its owned WSS connection');
            }),
          ]);
          assert.equal(tenantChecks, 2);
          assert.ok(messages.every((message) => !/connection_ack|"next"/.test(message)));
          assert.ok(messages.every((message) => !message.includes(authorization)));
        }
        await closing;
        for (let turn = 0; turn < 100 && f.service.stats().activeOperations; turn++)
          await setImmediate();
        assert.deepEqual(
          { policies, mutations, getters, allocated },
          {
            policies: 0,
            mutations: 0,
            getters: 0,
            allocated: 0,
          },
        );
        assert.equal(f.service.stats().activeOperations, 0);
        assert.equal(f.service.stats().activeSubscriptions, 0);
        assert.ok(!f.logs().includes(authorization));
        assert.doesNotMatch(f.logs(), /owned-private-retired-policy/);
      } finally {
        socket?.terminate();
        try {
          await closing;
        } finally {
          try {
            await f?.close();
          } finally {
            await tls.close();
          }
        }
      }
    },
  );
