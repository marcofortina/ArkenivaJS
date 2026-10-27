// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { performance } from 'node:perf_hooks';
import type { OperationOptions } from '@arkenivajs/core';
import type { AmqpService, AmqpPublishReceipt, MessagingSubscription } from './contracts.js';
import type { Settings } from './settings.js';
import { identifier } from './settings.js';
import { fields, failure } from './validation.js';
import { operation, Task, maximumTimeout } from './operation.js';
import { Connection } from './connection.js';
import { publication, publish, unknownReceipt } from './publisher.js';
import { consumption, Subscription } from './subscription.js';
import type { Observers } from './observation.js';
import { recorder } from './observation.js';

export function managedService(
  settings: Settings,
  application: AbortSignal,
  ready: () => boolean,
  observers: Observers = {},
) {
  const observe = recorder(observers),
    owners = new Map(
      settings.connections.map((config) => [
        config.name,
        new Connection(settings, config, (name) => observe.event(name)),
      ]),
    ),
    active = new Set<Task<unknown>>(),
    publishCounts = new Map<string, number>(),
    subscriptions = new Map<string, Subscription>(),
    healthBusy = new Set<Connection>(),
    cleanupSignal = new AbortController().signal;
  let cleaned = false,
    closing = false,
    closingTask: Task<void> | undefined;
  const check = () => {
    if (closing || application.aborted) throw failure('EK_RESOURCE_CLOSED');
    if (!ready()) throw failure('EK_LIFECYCLE_STATE');
  };
  const owner = (name: unknown) => {
    const value = owners.get(identifier(name));
    if (!value) throw failure('EK_AMQP_CONFIG');
    return value;
  };
  const requested = (options: OperationOptions | undefined) => {
    const value = operation(options);
    if (value.signal?.aborted) throw failure('EK_ABORTED');
  };
  function track<T>(
    task: Task<T>,
    kind: 'connect' | 'publish' | 'subscribe' | 'health' | 'unsubscribe',
    released: () => void = () => undefined,
  ) {
    const started = performance.now();
    active.add(task as Task<unknown>);
    const finished = task.done.finally(() => {
      active.delete(task as Task<unknown>);
      released();
    });
    const result = task.result.then(
      async (value) => {
        if (!task.controller.signal.aborted) await finished;
        const receipt = kind === 'publish' ? (value as AmqpPublishReceipt) : undefined;
        observe.complete(kind, receipt?.status ?? 'ok', Math.max(0, performance.now() - started));
        return value;
      },
      async (error: unknown) => {
        if (!task.controller.signal.aborted) await finished;
        observe.complete(kind, 'error', Math.max(0, performance.now() - started));
        throw error;
      },
    );
    void result.catch(() => undefined);
    return result;
  }
  const service = Object.freeze<AmqpService>({
    async publish(input, options) {
      check();
      requested(options);
      const connection = owner(fields(input).connection),
        count = publishCounts.get(connection.config.name) ?? 0;
      if (!connection.available || connection.brokerBlocked || connection.writeBlocked)
        throw failure('EK_AMQP_CONNECT');
      if (count >= connection.config.maxInFlightPublishes) throw failure('EK_AMQP_PUBLISH');
      publishCounts.set(connection.config.name, count + 1);
      let value: ReturnType<typeof publication>;
      try {
        value = publication(input, connection);
      } catch (error) {
        publishCounts.set(connection.config.name, count);
        throw error;
      }
      const owned: { task?: Task<AmqpPublishReceipt> } = {};
      const task = new Task<AmqpPublishReceipt>(
        options,
        application,
        () => {
          if (owned.task?.submitted) connection.reset();
        },
        (task) => publish(connection, value, task),
        () => unknownReceipt(value.messageId),
        'EK_AMQP_PUBLISH',
      );
      owned.task = task;
      observe.publication(
        value.body.length,
        [...publishCounts.values()].reduce((sum, count) => sum + count, 0),
      );
      return track(task, 'publish', () => {
        value.body.fill(0);
        publishCounts.set(
          connection.config.name,
          (publishCounts.get(connection.config.name) ?? 1) - 1,
        );
        observe.inFlight([...publishCounts.values()].reduce((sum, count) => sum + count, 0));
      });
    },
    async subscribe(input, handler, options) {
      check();
      requested(options);
      if (typeof handler !== 'function') throw failure('EK_AMQP_CONSUME');
      const connection = owner(fields(input).connection),
        config = consumption(input, connection),
        key = connection.config.name + '\0' + config.queue;
      if (!connection.available) throw failure('EK_AMQP_CONNECT');
      const current = [...subscriptions.values()].filter((entry) => entry.owner === connection);
      if (
        subscriptions.has(key) ||
        current.length >= 8 ||
        current.reduce(
          (bytes, entry) => bytes + entry.config.prefetch * entry.config.maxMessageBytes,
          config.prefetch * config.maxMessageBytes,
        ) >
          64 * 1024 * 1024
      )
        throw failure('EK_AMQP_CONSUME');
      const subscription = new Subscription(connection, config, handler, (outcome, bytes) =>
        observe.event(outcome, bytes),
      );
      subscriptions.set(key, subscription);
      connection.restored.add(subscription.restore);
      let started = false;
      const task = new Task<void>(
        options,
        application,
        () => {
          subscription.closed = true;
          connection.restored.delete(subscription.restore);
          if (started) connection.reset();
        },
        async (task) => {
          try {
            task.check();
            started = true;
            await task.wait(subscription.open());
          } catch {
            await subscription.cancel();
            await subscription.drain();
            subscriptions.delete(key);
            task.check();
            throw failure('EK_AMQP_CONSUME');
          }
        },
        undefined,
        'EK_AMQP_CONSUME',
      );
      await track(task, 'subscribe');
      let closeTask: Task<void> | undefined,
        drained = false;
      return Object.freeze<MessagingSubscription>({
        async close(options) {
          operation(options);
          if (options?.signal?.aborted) throw failure('EK_ABORTED');
          if (!closeTask) {
            closeTask = new Task(
              { timeoutMs: maximumTimeout },
              cleanupSignal,
              () => connection.reset(),
              async () => {
                await subscription.cancel();
                await subscription.drain();
                subscriptions.delete(key);
                drained = true;
              },
            );
            void track(closeTask, 'unsubscribe').catch(() => undefined);
          }
          const owned = closeTask;
          return new Task<void>(
            options,
            cleanupSignal,
            () => connection.reset(),
            async (task) => {
              await task.wait(owned.done);
              if (!drained) throw failure('EK_AMQP_CONSUME');
            },
          ).result;
        },
      });
    },
    async health(name, options) {
      check();
      requested(options);
      const connection = owner(name);
      if (!connection.available)
        return Object.freeze({ available: false, checkedAt: new Date().toISOString() });
      if (healthBusy.has(connection)) throw failure('EK_AMQP_CONNECT');
      healthBusy.add(connection);
      let started = false;
      const task = new Task<Readonly<{ available: boolean; checkedAt: string }>>(
        options,
        application,
        () => {
          if (started) connection.reset();
        },
        async (task) => {
          task.check();
          started = true;
          const model = connection.model;
          if (!model)
            return Object.freeze({ available: false, checkedAt: new Date().toISOString() });
          const channel = await task.wait(model.createChannel());
          channel.on('error', () => undefined);
          try {
            const exchange = connection.config.topology.exchanges[0],
              queue = connection.config.topology.queues[0];
            if (exchange) await task.wait(channel.checkExchange(exchange.name));
            else if (queue) await task.wait(channel.checkQueue(queue.name));
            return Object.freeze({ available: true, checkedAt: new Date().toISOString() });
          } catch {
            task.check();
            return Object.freeze({ available: false, checkedAt: new Date().toISOString() });
          } finally {
            await channel.close().catch(() => undefined);
          }
        },
      );
      return track(task, 'health', () => healthBusy.delete(connection));
    },
    native(name) {
      check();
      const connection = owner(name);
      if (!connection.available || !connection.model) throw failure('EK_AMQP_CONNECT');
      return connection.model;
    },
    async close(requested) {
      operation(requested);
      if (requested?.signal?.aborted) throw failure('EK_ABORTED');
      if (!closingTask) {
        closing = true;
        closingTask = new Task(
          { timeoutMs: maximumTimeout },
          cleanupSignal,
          () => {
            for (const connection of owners.values()) void connection.close();
          },
          async () => {
            await Promise.all([...subscriptions.values()].map((entry) => entry.cancel()));
            await Promise.allSettled([...active].map((task) => task.done));
            await Promise.all([...subscriptions.values()].map((entry) => entry.drain()));
            await Promise.all([...owners.values()].map((connection) => connection.close()));
            subscriptions.clear();
            cleaned = true;
          },
        );
      }
      const owned = closingTask;
      return new Task<void>(
        requested,
        cleanupSignal,
        () => {
          for (const connection of owners.values()) void connection.close();
        },
        async (task) => {
          await task.wait(owned.done);
          if (!cleaned) throw failure('EK_AMQP_CONNECT');
        },
      ).result;
    },
  });
  return {
    service,
    async init() {
      for (const connection of owners.values()) {
        const task = new Task<void>(
          undefined,
          application,
          () => {
            void connection.close();
          },
          (task) => connection.init(task),
        );
        await track(task, 'connect');
      }
    },
    async close() {
      return service.close();
    },
  };
}
