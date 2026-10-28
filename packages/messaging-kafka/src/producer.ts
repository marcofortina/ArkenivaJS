// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { performance } from 'node:perf_hooks';
import type { OperationOptions } from '@arkenivajs/core';
import type { KafkaJS } from '@confluentinc/kafka-javascript';
import type { KafkaService, KafkaHeaders, KafkaPublicationReceipt } from './contracts.js';
import type { Settings } from './settings.js';
import { Connection } from './native.js';
import { operation, Task } from './operation.js';
import { publication } from './payload.js';
import { fields, text, integer, offset, failure } from './validation.js';
import { recorder } from './observation.js';
import type { Recorder } from './observation.js';

function nativeHeaders(input: KafkaHeaders): KafkaJS.IHeaders {
  const output: KafkaJS.IHeaders = Object.create(null);
  const value = (item: string | Uint8Array | null): string | Buffer | null =>
    item === null || typeof item === 'string'
      ? item
      : Buffer.isBuffer(item)
        ? item
        : Buffer.from(item);
  for (const [key, item] of Object.entries(input))
    output[key] = Array.isArray(item) ? item.map(value) : value(item as string | Uint8Array | null);
  return output;
}

/** Retain producer admission until its native operation physically settles. */
export function managedProducer(
  selected: Settings,
  application: AbortSignal,
  ready: () => boolean,
  environment: string,
  observed: Recorder = recorder(),
) {
  if (selected.resolverUsage === 'test-only' && environment !== 'test') throw failure();
  const stop = new AbortController();
  const signal = AbortSignal.any([application, stop.signal]);
  const connections = new Map(
    selected.clusters.map((config) => [
      config.name,
      new Connection(config, selected, environment, observed),
    ]),
  );
  const active = new Set<Task<unknown>>();
  const counts = new Map<Connection, number>();
  const healthBusy = new Set<Connection>();
  let closing: Promise<void> | undefined;
  const check = () => {
    if (signal.aborted || closing) throw failure('EK_RESOURCE_CLOSED');
    if (!ready()) throw failure('EK_LIFECYCLE_STATE');
  };
  const owner = (name: unknown): Connection => {
    const connection = connections.get(text(name, 128));
    if (!connection) throw failure();
    return connection;
  };
  function track<T>(task: Task<T>, release: () => void = () => undefined): Promise<T> {
    active.add(task as Task<unknown>);
    void task.done.then(() => {
      active.delete(task as Task<unknown>);
      release();
    });
    return task.result;
  }
  function shutdown(): Promise<void> {
    return (closing ??= (async () => {
      stop.abort();
      const resources = await Promise.allSettled(
        [...connections.values()].map((connection) => connection.close()),
      );
      await Promise.all([...active].map((task) => task.done));
      if (resources.some((result) => result.status === 'rejected'))
        throw failure('EK_KAFKA_CONNECT');
    })());
  }
  const service: Pick<KafkaService, 'publish' | 'health' | 'native' | 'close'> = Object.freeze({
    async publish(input, requested) {
      const options = operation(requested);
      if (options.signal?.aborted) throw failure('EK_ABORTED');
      check();
      const source = fields(input, ['cluster', 'topic', 'value', 'key', 'headers', 'messageId']);
      const connection = owner(source.cluster),
        current = counts.get(connection) ?? 0;
      if (current >= connection.config.maxBufferedMessages) throw failure('EK_KAFKA_PUBLISH');
      counts.set(connection, current + 1);
      try {
        // Admission precedes copying, and the copy precedes the first asynchronous yield.
        const snapshot = publication(source, connection.config.maxMessageBytes);
        if (!connection.config.topics.includes(snapshot.topic)) throw failure();
        const session = observed.current();
        observed.inFlight(connection.config.name, 'publish', current + 1);
        const message: KafkaJS.Message<Buffer, Buffer> = {
          value: snapshot.value === null ? null : (snapshot.value as Buffer),
          ...(snapshot.key === undefined ? {} : { key: snapshot.key as Buffer }),
          headers: nativeHeaders(snapshot.headers!),
        };
        const task = new Task<KafkaPublicationReceipt>(
          options,
          signal,
          () => undefined,
          async (task) => {
            task.check();
            task.submitted = true;
            const started = performance.now();
            observed.bytes(
              'publish',
              connection.config.name,
              snapshot.topic,
              snapshot.value,
              snapshot.key,
              snapshot.headers!,
              session,
            );
            const receipts = await observed.execute(
              connection.config.name,
              snapshot.topic,
              'publish',
              async () => {
                try {
                  return await connection
                    .producer()
                    .send({ topic: snapshot.topic, messages: [message] });
                } catch {
                  throw failure('EK_KAFKA_PUBLISH', true);
                }
              },
            );
            if (
              receipts.length !== 1 ||
              receipts[0]!.errorCode !== 0 ||
              receipts[0]!.topicName !== snapshot.topic
            )
              throw failure('EK_KAFKA_PUBLISH', true);
            const receipt = receipts[0]!;
            let position: string, partition: number;
            try {
              position = offset(receipt.baseOffset ?? receipt.offset);
              partition = integer(receipt.partition, 2147483647, 0);
            } catch {
              throw failure('EK_KAFKA_PUBLISH', true);
            }
            observed.latency(
              connection.config.name,
              snapshot.topic,
              'delivery',
              performance.now() - started,
            );
            task.check();
            return Object.freeze({
              topic: snapshot.topic,
              partition,
              offset: position,
              status: 'acknowledged' as const,
              ...(snapshot.messageId === undefined ? {} : { messageId: snapshot.messageId }),
            });
          },
          'EK_KAFKA_PUBLISH',
        );
        return track(task, () => {
          const remaining = (counts.get(connection) ?? 1) - 1;
          counts.set(connection, remaining);
          observed.inFlight(connection.config.name, 'publish', remaining);
        });
      } catch (error) {
        counts.set(connection, current);
        throw error;
      }
    },
    async health(name, requested) {
      const options = operation(requested);
      if (options.signal?.aborted) throw failure('EK_ABORTED');
      check();
      const connection = owner(name);
      if (healthBusy.has(connection)) throw failure('EK_KAFKA_CONNECT');
      healthBusy.add(connection);
      const task = new Task<Readonly<{ available: boolean; checkedAt: string }>>(
        options,
        signal,
        () => undefined,
        async (task) => {
          try {
            const metadata = await task.wait(
              connection.admin().fetchTopicMetadata({ topics: [...connection.config.topics] }),
            );
            return Object.freeze({
              available:
                metadata.length === connection.config.topics.length &&
                metadata.every(
                  (entry) =>
                    connection.config.topics.includes(entry.name) && entry.partitions.length > 0,
                ),
              checkedAt: new Date().toISOString(),
            });
          } catch (error) {
            if (error instanceof KitError && ['EK_ABORTED', 'EK_TIMEOUT'].includes(error.code))
              throw error;
            return Object.freeze({ available: false, checkedAt: new Date().toISOString() });
          }
        },
        'EK_KAFKA_CONNECT',
      );
      return track(task, () => healthBusy.delete(connection));
    },
    native(name) {
      check();
      const connection = owner(name);
      observed.event(connection.config.name, 'native-uninstrumented');
      return connection.producer();
    },
    close(requested) {
      const options = operation(requested);
      if (options.signal?.aborted) return Promise.reject(failure('EK_ABORTED'));
      const cleanup = shutdown();
      return new Task<void>(
        options,
        new AbortController().signal,
        () => undefined,
        async (task) => task.wait(cleanup),
        'EK_KAFKA_CONNECT',
      ).result;
    },
  });
  return {
    service,
    connections,
    shutdown,
    async init(): Promise<void> {
      if (signal.aborted || closing) throw failure('EK_RESOURCE_CLOSED');
      try {
        for (const connection of connections.values()) {
          const task = new Task<void>(
            undefined,
            signal,
            () => undefined,
            (task) => connection.open(task),
            'EK_KAFKA_CONNECT',
          );
          try {
            await track(task);
            observed.event(connection.config.name, 'connected');
          } catch (error) {
            observed.event(connection.config.name, 'connect-error');
            throw error;
          }
        }
      } catch (error) {
        void service.close().catch(() => undefined);
        throw error;
      }
    },
    close: (options?: OperationOptions) => service.close(options),
  };
}
