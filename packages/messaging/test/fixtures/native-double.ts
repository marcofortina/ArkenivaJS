// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Readable } from 'node:stream';
import nats from 'nats';
import type {
  ConnectionOptions,
  Msg,
  NatsConnection,
  NatsError,
  Status,
  SubscriptionOptions,
} from 'nats';

export function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void, reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

/** Faults replace only the SDK's public boundary; real broker integration is a separate required gate. */
export function nativeDouble() {
  const statuses = new Readable({ objectMode: true, read() {} }),
    ended = deferred<void>();
  const faults = new Map<string, unknown>(),
    frames: { subject: string; bytes: Uint8Array }[] = [],
    configurations: ConnectionOptions[] = [];
  const subscriptions = new Set<{
    subject: string;
    options: SubscriptionOptions;
    active: boolean;
    ended: ReturnType<typeof deferred<void>>;
  }>();
  let closed = false,
    draining = false,
    connects = 0,
    closes = 0,
    drains = 0,
    flushes = 0;
  let flushGate: Promise<void> | undefined,
    connectGate: Promise<void> | undefined,
    drainGate: Promise<void> | undefined;
  const client = {
    info: { max_payload: 1048576, version: '2.15.1' } as
      { max_payload: number; version: string } | undefined,
    status: () => statuses as AsyncIterable<Status>,
    closed: () => ended.promise,
    isClosed: () => closed,
    isDraining: () => draining,
    async flush() {
      flushes++;
      if (flushGate) await flushGate;
      if (faults.has('flush')) throw faults.get('flush');
      if (closed) throw new Error('Native connection closed');
    },
    publish(subject: string, bytes: Uint8Array) {
      if (faults.has('publish')) throw faults.get('publish');
      frames.push({ subject, bytes: Uint8Array.from(bytes) });
      queueMicrotask(() => {
        for (const subscription of subscriptions)
          if (subscription.active && subscription.subject === subject)
            subscription.options.callback!(null, { subject, data: bytes } as Msg);
      });
    },
    subscribe(subject: string, options: SubscriptionOptions) {
      if (faults.has('subscribe')) throw faults.get('subscribe');
      const owner = { subject, options, active: true, ended: deferred<void>() };
      subscriptions.add(owner);
      return {
        closed: owner.ended.promise,
        unsubscribe() {
          if (faults.has('unsubscribe')) throw faults.get('unsubscribe');
          owner.active = false;
          owner.ended.resolve();
        },
      };
    },
    async close() {
      closes++;
      if (faults.has('close')) throw faults.get('close');
      closed = true;
      client.info = undefined;
      for (const subscription of subscriptions) {
        subscription.active = false;
        subscription.ended.resolve();
      }
      statuses.push(null);
      ended.resolve();
    },
    async drain() {
      drains++;
      draining = true;
      if (drainGate) await drainGate;
      if (faults.has('drain')) throw faults.get('drain');
      await client.close();
    },
  };
  const connect = async (options: ConnectionOptions = {}) => {
    connects++;
    configurations.push(options);
    if (connectGate) await connectGate;
    if (faults.has('connect')) throw faults.get('connect');
    return client as unknown as NatsConnection;
  };
  return {
    connect,
    client,
    faults,
    frames,
    configurations,
    flushGate(value?: Promise<void>) {
      flushGate = value;
    },
    connectGate(value?: Promise<void>) {
      connectGate = value;
    },
    drainGate(value?: Promise<void>) {
      drainGate = value;
    },
    status(type: Status['type'], data: Status['data'] = '') {
      if (type === nats.Events.Disconnect) client.info = undefined;
      if (type === nats.Events.Reconnect) client.info = { max_payload: 1048576, version: '2.15.1' };
      statuses.push({ type, data });
    },
    failStatus(cause: Error) {
      statuses.destroy(cause);
    },
    deliver(subject: string, data: Uint8Array) {
      for (const subscription of subscriptions)
        if (subscription.active && subscription.subject === subject)
          subscription.options.callback!(null, { subject, data } as Msg);
    },
    subscriptionError(cause: NatsError) {
      for (const subscription of subscriptions)
        if (subscription.active) subscription.options.callback!(cause, undefined as never);
    },
    get counts() {
      return {
        connects,
        closes,
        drains,
        flushes,
        subscriptions: [...subscriptions].filter((entry) => entry.active).length,
      };
    },
  };
}
