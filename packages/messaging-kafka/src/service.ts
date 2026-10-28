// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncResource } from 'node:async_hooks';
import type { OperationOptions } from '@arkenivajs/core';
import type { KafkaService } from './contracts.js';
import type { Settings } from './settings.js';
import { managedProducer } from './producer.js';
import { consumption, Subscription } from './subscription.js';
import { operation, Task } from './operation.js';
import { failure, fields, text } from './validation.js';
import { recorder } from './observation.js';
import type { Observers } from './observation.js';

/** The owner keeps native group callbacks outside request and driver lock contexts. */
export function managedService(
  selected: Settings,
  application: AbortSignal,
  ready: () => boolean,
  environment: string,
  report: (code: string) => void = () => undefined,
  ports: Observers = {},
) {
  const observed = recorder(ports);
  const subscriptions = new Set<Subscription>();
  const ownsDelivery = () => [...subscriptions].some((subscription) => subscription.ownsDelivery());
  const producer = managedProducer(
    selected,
    application,
    () => ready() || ownsDelivery(),
    environment,
    observed,
  );
  const resource = new AsyncResource('arkenivajs.kafka.owner');
  const stop = new AbortController();
  const signal = AbortSignal.any([application, stop.signal]);
  const starting = new Set<Task<void>>();
  let closing: Promise<void> | undefined;
  const failed = new Set<string>();
  const dispatch = <T>(work: () => Promise<T>): Promise<T> => resource.runInAsyncScope(work);
  const service = Object.freeze<KafkaService>({
    ...producer.service,
    publish(input, options) {
      if (closing && !ownsDelivery()) return Promise.reject(failure('EK_RESOURCE_CLOSED'));
      return producer.service.publish(input, options);
    },
    native(cluster) {
      if (closing) throw failure('EK_RESOURCE_CLOSED');
      return producer.service.native(cluster);
    },
    async consume(input, handler, requested) {
      const options = operation(requested);
      if (options.signal?.aborted) throw failure('EK_ABORTED');
      if (signal.aborted || closing) throw failure('EK_RESOURCE_CLOSED');
      if (!ready()) throw failure('EK_LIFECYCLE_STATE');
      const source = fields(input, [
        'cluster',
        'topics',
        'groupId',
        'offsetReset',
        'maxInFlightPerPartition',
        'failurePolicy',
      ]);
      const connection = producer.connections.get(text(source.cluster, 128));
      if (!connection) throw failure();
      const config = consumption(source, connection);
      if (subscriptions.size >= 16) throw failure('EK_KAFKA_CONSUME');
      const subscription = new Subscription(
        connection,
        config,
        handler,
        signal,
        options,
        dispatch,
        (code) => {
          failed.add(connection.config.name);
          report(code);
        },
        () => subscriptions.delete(subscription),
        observed,
      );
      subscriptions.add(subscription);
      const task = new Task<void>(
        options,
        signal,
        () => {
          void subscription.close().catch(() => undefined);
        },
        (task) => subscription.start(task),
        'EK_KAFKA_CONSUME',
      );
      starting.add(task);
      void task.done.then(() => starting.delete(task));
      try {
        await task.result;
        return subscription.handle;
      } catch (error) {
        void subscription.close().catch(() => undefined);
        throw error;
      }
    },
    async health(cluster, options) {
      if (closing) throw failure('EK_RESOURCE_CLOSED');
      const result = await producer.service.health(cluster, options);
      return failed.has(cluster) ? Object.freeze({ ...result, available: false }) : result;
    },
    close(requested) {
      const options = operation(requested);
      if (ownsDelivery()) return Promise.reject(failure('EK_LIFECYCLE_STATE'));
      if (options.signal?.aborted) return Promise.reject(failure('EK_ABORTED'));
      closing ??= (async () => {
        const results = await Promise.allSettled(
          [...subscriptions].map((subscription) => subscription.shutdown()),
        );
        stop.abort();
        const producers = await Promise.allSettled([producer.shutdown()]);
        await Promise.all([...starting].map((task) => task.done));
        resource.emitDestroy();
        if ([...results, ...producers].some((result) => result.status === 'rejected'))
          throw failure('EK_KAFKA_CONSUME');
      })();
      return new Task<void>(
        options,
        new AbortController().signal,
        () => {
          stop.abort();
          void producer.shutdown().catch(() => undefined);
        },
        (task) => task.wait(closing!),
        'EK_KAFKA_CONSUME',
      ).result;
    },
  });
  return {
    service,
    init: () => producer.init(),
    close: (options?: OperationOptions) => service.close(options),
  };
}
