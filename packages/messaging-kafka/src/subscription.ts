// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { AsyncLocalStorage } from 'node:async_hooks';
import { types } from 'node:util';
import { performance } from 'node:perf_hooks';
import { within } from '@arkenivajs/core/support';
import { KitError } from '@arkenivajs/core';
import type { OperationOptions } from '@arkenivajs/core';
import type { KafkaJS } from '@confluentinc/kafka-javascript';
import type { KafkaConsumeSettings, KafkaRecord, MessagingSubscription } from './contracts.js';
import type { Connection } from './native.js';
import { operation, Task } from './operation.js';
import { headers } from './payload.js';
import { array, bytes, fields, text, topic, integer, offset, failure } from './validation.js';
import type { Recorder } from './observation.js';

const deliveryScope = new AsyncLocalStorage<{ owner: Subscription; active: boolean }>();
type Dispatch = <T>(work: () => Promise<T>) => Promise<T>;
type Part = Readonly<{ topic: string; partition: number }>;
const key = (value: Part) => value.topic + ':' + value.partition;

export function consumption(input: unknown, connection: Connection): KafkaConsumeSettings {
  const value = fields(input, [
    'cluster',
    'topics',
    'groupId',
    'offsetReset',
    'maxInFlightPerPartition',
    'failurePolicy',
  ]);
  const topics = array(value.topics, 64).map(topic),
    groupId = text(value.groupId, 128);
  if (
    !topics.length ||
    new Set(topics).size !== topics.length ||
    topics.some((name) => !connection.config.topics.includes(name)) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(groupId) ||
    !['earliest', 'latest'].includes(value.offsetReset as string) ||
    (value.maxInFlightPerPartition !== undefined && value.maxInFlightPerPartition !== 1) ||
    (value.failurePolicy !== undefined && value.failurePolicy !== 'stop')
  )
    throw failure();
  return Object.freeze({
    cluster: connection.config.name,
    topics: Object.freeze(topics),
    groupId,
    offsetReset: value.offsetReset as 'earliest' | 'latest',
    maxInFlightPerPartition: 1,
    failurePolicy: 'stop',
  });
}

/** Native group leases gate commits; callback completion alone cannot authorize an offset update. */
export class Subscription {
  private readonly stop = new AbortController();
  private readonly signal: AbortSignal;
  private readonly leases = new Map<string, symbol>();
  private readonly committed = new Map<string, bigint>();
  private readonly active = new Set<Task<void>>();
  private consumer: KafkaJS.Consumer<Buffer, Buffer> | undefined;
  private connecting: Promise<void> | undefined;
  private cleanup: Promise<void> | undefined;
  private stopping = false;
  private fault: KitError | undefined;
  readonly handle: MessagingSubscription;
  ownsDelivery(): boolean {
    const scope = deliveryScope.getStore();
    return scope?.owner === this && scope.active;
  }
  constructor(
    private readonly connection: Connection,
    private readonly config: KafkaConsumeSettings,
    private readonly handler: (value: KafkaRecord) => Promise<void>,
    application: AbortSignal,
    private readonly requested: ReturnType<typeof operation>,
    private readonly dispatch: Dispatch,
    private readonly report: (code: string) => void,
    private readonly released: () => void,
    private readonly observed: Recorder,
  ) {
    if (typeof handler !== 'function' || types.isProxy(handler)) throw failure();
    this.signal = AbortSignal.any([
      application,
      ...(requested.signal ? [requested.signal] : []),
      this.stop.signal,
    ]);
    this.handle = Object.freeze({ close: (options?: OperationOptions) => this.close(options) });
    this.signal.addEventListener('abort', () => this.requestStop(), { once: true });
  }
  async start(task: Task<unknown>): Promise<void> {
    task.check();
    if (this.signal.aborted || this.stopping) throw failure('EK_ABORTED');
    this.consumer = this.connection.consumer(
      this.config.groupId,
      this.config.offsetReset,
      (error: { code?: number }, assignment: Part[], functions: { assignmentLost(): boolean }) =>
        this.dispatch(() => this.rebalance(error.code, assignment, functions.assignmentLost())),
    );
    this.connecting = this.consumer.connect();
    await task.wait(this.connecting);
    if (this.signal.aborted || this.stopping) throw failure('EK_ABORTED');
    await task.wait(this.consumer.subscribe({ topics: [...this.config.topics] }));
    await task.wait(
      this.consumer.run({
        partitionsConsumedConcurrently: 1,
        eachMessage: (payload) =>
          this.dispatch(async () => {
            try {
              await this.process(payload);
            } catch (error) {
              if (!this.signal.aborted && !this.stopping)
                this.requestStop(error instanceof KitError ? error : failure('EK_KAFKA_CONSUME'));
              throw error;
            }
          }),
      }),
    );
  }
  private async rebalance(
    code: number | undefined,
    assignment: readonly Part[],
    lost: boolean,
  ): Promise<void> {
    try {
      const kind = this.connection.rebalanceKind(code);
      if (kind !== 'error')
        this.observed.event(
          this.connection.config.name,
          kind === 'assign' ? 'assigned' : 'revoked',
        );
      if (assignment.length > 1024) throw failure('EK_KAFKA_REBALANCE');
      for (const part of assignment) {
        if (!this.config.topics.includes(part.topic)) throw failure('EK_KAFKA_REBALANCE');
        integer(part.partition, 1023, 0);
        this.leases.delete(key(part));
        this.committed.delete(key(part));
      }
      if (kind === 'revoke' || lost || this.signal.aborted) return;
      if (kind !== 'assign') throw failure('EK_KAFKA_REBALANCE');
      const values = await this.consumer!.committed([...assignment], 2000);
      if (this.signal.aborted) return;
      if (values.length !== assignment.length) throw failure('EK_KAFKA_REBALANCE');
      for (const part of assignment) {
        const value = values.find(
          (entry) => entry.topic === part.topic && entry.partition === part.partition,
        );
        if (!value) throw failure('EK_KAFKA_REBALANCE');
        const position =
          value.offset == null || value.offset === '-1001' ? 0n : BigInt(offset(value.offset));
        this.committed.set(key(part), position);
        this.leases.set(key(part), Symbol('kafka.partition.lease'));
      }
    } catch {
      this.requestStop(failure('EK_KAFKA_REBALANCE'));
    }
  }
  private owns(part: Part, lease: symbol | undefined): boolean {
    return (
      !this.signal.aborted &&
      lease !== undefined &&
      this.leases.get(key(part)) === lease &&
      this.consumer!.assignment().some(
        (current) => current.topic === part.topic && current.partition === part.partition,
      )
    );
  }
  private async process(payload: KafkaJS.EachMessagePayload<Buffer, Buffer>): Promise<void> {
    if (this.signal.aborted || this.stopping) throw failure('EK_ABORTED');
    const part = { topic: payload.topic, partition: integer(payload.partition, 2147483647, 0) };
    const lease = this.leases.get(key(part));
    if (!this.owns(part, lease)) throw failure('EK_KAFKA_REBALANCE');
    const position = BigInt(offset(payload.message.offset));
    if (position < (this.committed.get(key(part)) ?? 0n)) return;
    const native = payload.message;
    const body =
      native.value === null ? null : bytes(native.value, this.connection.config.maxMessageBytes);
    const messageKey =
      native.key == null ? undefined : bytes(native.key, this.connection.config.maxMessageBytes);
    if (
      (body?.byteLength ?? 0) + (messageKey?.byteLength ?? 0) >
      this.connection.config.maxMessageBytes
    )
      throw failure('EK_KAFKA_CONSUME');
    const record: KafkaRecord = Object.freeze({
      topic: part.topic,
      partition: part.partition,
      offset: position.toString(),
      value: body,
      ...(messageKey === undefined ? {} : { key: messageKey }),
      headers: headers(native.headers),
      ...(native.timestamp && native.timestamp !== '-1'
        ? { timestamp: offset(native.timestamp) }
        : {}),
    });
    this.observed.bytes(
      'consume',
      this.connection.config.name,
      part.topic,
      record.value,
      record.key,
      record.headers,
    );
    const task = new Task<void>(
      { timeoutMs: this.requested.timeoutMs },
      this.signal,
      () => undefined,
      async (task) => {
        task.check();
        let returned: unknown;
        const started = performance.now();
        try {
          returned = await this.observed.execute(
            this.connection.config.name,
            part.topic,
            'consume',
            async () => {
              const scope = { owner: this, active: true };
              try {
                return await deliveryScope.run(scope, () => this.handler(record));
              } catch {
                throw failure('EK_KAFKA_CONSUME');
              } finally {
                scope.active = false;
              }
            },
          );
        } catch {
          throw failure('EK_KAFKA_CONSUME');
        } finally {
          this.observed.latency(
            this.connection.config.name,
            part.topic,
            'handler',
            performance.now() - started,
          );
        }
        if (returned !== undefined) throw failure('EK_KAFKA_CONSUME');
        task.check();
        if (!this.owns(part, lease)) throw failure('EK_KAFKA_REBALANCE');
        const next = position + 1n;
        if (next > 9223372036854775807n) throw failure('EK_KAFKA_OFFSET');
        task.submitted = true;
        try {
          await this.consumer!.commitOffsets([{ ...part, offset: next.toString() }]);
        } catch {
          this.observed.event(this.connection.config.name, 'offset-error', part.topic);
          throw failure('EK_KAFKA_OFFSET', true);
        }
        this.observed.event(this.connection.config.name, 'offset-committed', part.topic);
        task.check();
        if (!this.owns(part, lease)) throw failure('EK_KAFKA_REBALANCE', true);
        this.committed.set(key(part), next);
        this.connection.observeLag(part.topic, part.partition, next);
      },
      'EK_KAFKA_CONSUME',
    );
    this.active.add(task);
    this.observed.consumerActive(this.connection.config.name, 1);
    void task.done.then(() => {
      this.active.delete(task);
      this.observed.consumerActive(this.connection.config.name, -1);
    });
    try {
      await task.result;
    } catch (error) {
      if (!this.signal.aborted)
        this.requestStop(
          error instanceof KitError
            ? failure(error.code, error.details?.outcome === 'unknown')
            : failure('EK_KAFKA_CONSUME'),
        );
      throw error;
    }
  }
  private requestStop(error?: KitError, cancel = true): void {
    if (error && !this.fault) {
      this.fault = error;
      this.observed.event(this.connection.config.name, 'consumer-error');
      this.notify(error.code);
    }
    const first = !this.stopping;
    this.stopping = true;
    if (cancel) {
      this.stop.abort();
      this.leases.clear();
      this.committed.clear();
    }
    if (!first) return;
    // Dispatch outside the driver's callback lock; disconnect waits for callbacks to return.
    this.cleanup = this.dispatch(async () => {
      let disconnected = false;
      try {
        await this.consumer?.disconnect();
      } catch {
        /* Retry after an in-flight connection settles. */
      }
      await this.connecting?.catch(() => undefined);
      try {
        await this.consumer?.disconnect();
        disconnected = true;
      } finally {
        await Promise.all([...this.active].map((task) => task.done));
        if (disconnected) this.released();
      }
    });
    void this.cleanup.catch(() => {
      this.fault ??= failure('EK_KAFKA_CONSUME');
      this.notify(this.fault.code);
    });
  }
  private notify(code: string): void {
    try {
      this.report(code);
    } catch {
      /* Diagnostics cannot prevent resource cleanup. */
    }
  }
  async close(options?: OperationOptions): Promise<void> {
    const selected = operation(options);
    if (this.ownsDelivery()) throw failure('EK_LIFECYCLE_STATE');
    if (selected.signal?.aborted) throw failure('EK_ABORTED');
    this.requestStop(undefined, false);
    try {
      await within(() => this.cleanup!, selected);
    } catch (error) {
      this.requestStop();
      throw error;
    }
    if (this.fault) throw this.fault;
  }
  shutdown(): Promise<void> {
    this.requestStop(undefined, false);
    return this.cleanup!.then(() => {
      if (this.fault) throw this.fault;
    });
  }
}
