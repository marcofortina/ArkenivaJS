// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { EventEmitter } from 'node:events';
import type { TestContext } from 'node:test';
import redis from 'redis';
import type { RedisClientType } from 'redis';
import { RedisConnection } from '../../dist/connection.js';
import type { RedisObservationPorts } from '../../dist/connection.js';

type Method = 'get' | 'set' | 'del' | 'increment' | 'publish' | 'ping';
/** Fault plans model SDK boundaries; real Redis semantics have an independent integration suite. */
export interface Plan {
  value?: unknown;
  fail?: boolean;
  error?: unknown;
  gate?: Promise<void>;
}
export function sdkDouble(context: TestContext) {
  const client = new EventEmitter();
  // Each bounded in-flight fake command owns one close listener until it settles.
  client.setMaxListeners(144);
  let open = false,
    ready = false,
    connects = 0,
    destroys = 0;
  let connectGate = Promise.resolve(),
    connectError: unknown,
    connectFails = false,
    destroyError: unknown,
    destroyFails = false;
  const plans = new Map<Method, Plan[]>();
  const calls: { method: Method; arguments: unknown[]; signal: AbortSignal | undefined }[] = [];
  const mappings: unknown[] = [],
    configurations: unknown[] = [];
  Object.defineProperties(client, { isReady: { get: () => ready }, isOpen: { get: () => open } });
  const sdk = client as unknown as RedisClientType;
  Object.assign(client, {
    async connect() {
      connects++;
      open = true;
      await connectGate;
      if (connectFails) throw connectError;
      open = true;
      ready = true;
      return sdk;
    },
    destroy() {
      destroys++;
      open = false;
      ready = false;
      client.emit('closed');
      if (destroyFails) throw destroyError;
    },
    withAbortSignal(signal: AbortSignal) {
      const execute = async (method: Method, arguments_: unknown[]) => {
        calls.push({ method, arguments: arguments_, signal });
        const plan = plans.get(method)?.shift() ?? {};
        let detach = () => {};
        const cancelled = new Promise<never>((_resolve, reject) => {
          const abort = () => reject(new redis.AbortError());
          const close = () => reject(new redis.ClientClosedError());
          signal.addEventListener('abort', abort, { once: true });
          client.once('closed', close);
          detach = () => {
            signal.removeEventListener('abort', abort);
            client.removeListener('closed', close);
          };
          if (signal.aborted) abort();
        });
        try {
          await Promise.race([plan.gate ?? Promise.resolve(), cancelled]);
          if (plan.fail) throw plan.error;
          if ('value' in plan) return plan.value;
          return {
            get: Buffer.from('value'),
            set: 'OK',
            del: 1,
            increment: '1',
            publish: 0,
            ping: 'PONG',
          }[method];
        } finally {
          detach();
        }
      };
      const commands = {
        ping: () => execute('ping', []),
        set: (...arguments_: unknown[]) => execute('set', arguments_),
        del: (...arguments_: unknown[]) => execute('del', arguments_),
        eval: (...arguments_: unknown[]) => execute('increment', arguments_),
        evalRo: (...arguments_: unknown[]) => execute('get', arguments_),
        publish: (...arguments_: unknown[]) => execute('publish', arguments_),
        withTypeMapping(mapping: unknown) {
          mappings.push(mapping);
          return commands;
        },
      };
      return commands as unknown as RedisClientType;
    },
  });
  context.mock.method(redis, 'createClient', (configuration: unknown) => {
    configurations.push(configuration);
    return sdk;
  });
  return {
    client: sdk,
    calls,
    mappings,
    configurations,
    plan(method: Method, value: Plan) {
      const queue = plans.get(method) ?? [];
      queue.push(value);
      plans.set(method, queue);
    },
    ready(value: boolean) {
      ready = value;
    },
    gateConnect(value: Promise<void>) {
      connectGate = value;
    },
    failConnect(value: unknown) {
      connectFails = true;
      connectError = value;
    },
    failDestroy(value: unknown) {
      destroyFails = true;
      destroyError = value;
    },
    get counts() {
      return { connects, destroys };
    },
    connection(observation: RedisObservationPorts = {}) {
      return new RedisConnection(
        'test',
        {
          native: {
            socket: { host: '127.0.0.1', port: 1 },
            disableOfflineQueue: true,
            commandsQueueMaxLength: 128,
          },
          prefix: 'scope:',
        },
        observation,
      );
    },
  };
}
