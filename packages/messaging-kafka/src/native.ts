// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createRequire } from 'node:module';
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { performance } from 'node:perf_hooks';
import type { KafkaJS } from '@confluentinc/kafka-javascript';
import type { KafkaClusterConfig } from './contracts.js';
import type { Settings } from './settings.js';
import type { Task } from './operation.js';
import { failure, fields, text, offset } from './validation.js';
import { recorder } from './observation.js';
import type { Recorder } from './observation.js';

const require = createRequire(import.meta.url);
const quiet: KafkaJS.Logger = Object.freeze({
  info() {},
  error() {},
  warn() {},
  debug() {},
  namespace() {
    return this;
  },
  setLogLevel() {},
});

/** Read a bounded regular CA file once; the native client receives that exact PEM snapshot. */
async function certificate(path: string, task: Task<unknown>): Promise<string> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    task.check();
    const stat = await file.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > 1048576) throw failure();
    const buffer = Buffer.alloc(1048577);
    let size = 0;
    while (size < buffer.length) {
      task.check();
      const result = await file.read(buffer, size, buffer.length - size, size);
      if (!result.bytesRead) break;
      size += result.bytesRead;
    }
    task.check();
    if (!size || size > 1048576) throw failure();
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, size));
  } finally {
    await file.close();
  }
}

/** Every native client remains owned by one application and one named static cluster. */
export class Connection {
  private client: KafkaJS.Kafka | undefined;
  private writer: KafkaJS.Producer<Buffer, Buffer> | undefined;
  private administrator: KafkaJS.Admin | undefined;
  private closing: Promise<void> | undefined;
  private readonly connecting = new Set<Promise<unknown>>();
  private readonly probes = new Map<string, Promise<void>>();
  private readonly sampled = new Map<string, number>();
  constructor(
    readonly config: KafkaClusterConfig,
    private readonly selected: Settings,
    private readonly environment: string,
    private readonly observed: Recorder = recorder(),
  ) {}

  async open(task: Task<unknown>): Promise<void> {
    task.check();
    if (this.closing) throw failure('EK_RESOURCE_CLOSED');
    let library: typeof import('@confluentinc/kafka-javascript');
    try {
      library = require('@confluentinc/kafka-javascript') as typeof library;
      const local = createRequire(require.resolve('@confluentinc/kafka-javascript/package.json'));
      const binding: unknown = local('./librdkafka.js');
      if (
        !binding ||
        typeof binding !== 'object' ||
        Object.getOwnPropertyDescriptor(binding, 'arkenivajsNativeCompatibilityVersion')?.value !==
          1
      )
        throw failure('EK_KAFKA_CONFIG');
    } catch {
      throw failure('EK_KAFKA_CONFIG');
    }
    const credential = this.config.credentialSecretRef;
    let sasl: Readonly<{ mechanism: string; username: string; password: string }> | undefined;
    if (credential !== undefined) {
      if (!this.selected.resolveSecret) throw failure();
      const encoded = await task.wait(
        this.selected.resolveSecret(credential, {
          signal: task.controller.signal,
          timeoutMs: task.remaining(),
        }),
      );
      if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 16384) throw failure();
      let parsed: unknown;
      try {
        parsed = JSON.parse(encoded) as unknown;
      } catch {
        throw failure();
      }
      const value = fields(parsed, ['mechanism', 'username', 'password']);
      if (!['plain', 'scram-sha-256', 'scram-sha-512'].includes(value.mechanism as string))
        throw failure();
      sasl = Object.freeze({
        mechanism: (value.mechanism as string).toUpperCase(),
        username: text(value.username, 256),
        password: text(value.password, 4096),
      });
    }
    const ca =
      this.config.tlsCaFile === undefined
        ? undefined
        : await certificate(this.config.tlsCaFile, task);
    task.check();
    if (this.closing) throw failure('EK_RESOURCE_CLOSED');
    const plaintext =
      this.environment === 'test' &&
      !sasl &&
      !this.config.tlsCaFile &&
      this.config.brokers.every((broker) => /^(?:127\.0\.0\.1|localhost|\[::1\]):/.test(broker));
    const common: KafkaJS.CommonConstructorConfig = {
      'bootstrap.servers': this.config.brokers.join(','),
      'client.id': this.config.clientId,
      'security.protocol': plaintext ? 'plaintext' : sasl ? 'sasl_ssl' : 'ssl',
      ...(!plaintext
        ? {
            'enable.ssl.certificate.verification': true,
            'ssl.endpoint.identification.algorithm': 'https' as const,
            // TLS 1.2 suites exclude older protocol versions; TLS 1.3 keeps its native defaults.
            'ssl.cipher.suites': 'ECDHE+AESGCM:ECDHE+CHACHA20',
          }
        : {}),
      ...(ca === undefined ? {} : { 'ssl.ca.pem': ca }),
      ...(sasl
        ? {
            'sasl.mechanisms': sasl.mechanism,
            'sasl.username': sasl.username,
            'sasl.password': sasl.password,
          }
        : {}),
      'socket.timeout.ms': 10000,
      'socket.connection.setup.timeout.ms': 5000,
      'reconnect.backoff.ms': 100,
      'reconnect.backoff.max.ms': 1000,
      'allow.auto.create.topics': false,
      'receive.message.max.bytes': Math.max(1048576, this.config.maxMessageBytes + 65536),
      log_level: 0,
      kafkaJS: {
        brokers: [...this.config.brokers],
        logLevel: 0,
        logger: quiet,
        retry: { retries: 0 },
      },
    };
    this.client = new library.KafkaJS.Kafka(common);
    this.writer = this.client.producer<Buffer, Buffer>({
      kafkaJS: { idempotent: true, acks: -1, allowAutoTopicCreation: false },
      'enable.idempotence': true,
      acks: -1,
      'message.send.max.retries': 3,
      'max.in.flight.requests.per.connection': 5,
      'message.timeout.ms': 30000,
      'queue.buffering.max.messages': this.config.maxBufferedMessages,
      'queue.buffering.max.kbytes': Math.ceil(
        (this.config.maxBufferedMessages * (this.config.maxMessageBytes + 16384)) / 1024,
      ),
      'message.max.bytes': Math.max(1000, this.config.maxMessageBytes + 65536),
    });
    const connected = this.writer.connect();
    this.track(connected);
    try {
      await task.wait(connected);
    } catch (error) {
      const code =
        error && typeof error === 'object'
          ? Object.getOwnPropertyDescriptor(error, 'code')?.value
          : undefined;
      if (
        code === library.KafkaJS.ErrorCodes.ERR_SASL_AUTHENTICATION_FAILED ||
        code === library.KafkaJS.ErrorCodes.ERR__AUTHENTICATION
      )
        this.observed.event(this.config.name, 'authentication-error');
      throw error;
    }
    if (this.closing) throw failure('EK_RESOURCE_CLOSED');
    this.administrator = this.writer.dependentAdmin();
    const administrative = this.administrator.connect();
    this.track(administrative);
    await task.wait(administrative);
    const metadata = await task.wait(
      this.administrator.fetchTopicMetadata({ topics: [...this.config.topics] }),
    );
    if (
      metadata.length !== this.config.topics.length ||
      metadata.reduce((count, entry) => count + entry.partitions.length, 0) > 1024 ||
      metadata.some((entry) => !this.config.topics.includes(entry.name) || !entry.partitions.length)
    )
      throw failure();
  }

  observeLag(topic: string, partition: number, next: bigint): void {
    const now = performance.now();
    const name = topic + ':' + partition;
    if (
      this.closing ||
      this.probes.has(name) ||
      this.probes.size >= 4 ||
      now - (this.sampled.get(name) ?? -Infinity) < 5000
    )
      return;
    if (!this.sampled.has(name) && this.sampled.size >= 1024)
      this.sampled.delete(this.sampled.keys().next().value!);
    this.sampled.set(name, now);
    const probe = Promise.resolve()
      .then(async () => {
        try {
          const library =
            require('@confluentinc/kafka-javascript') as typeof import('@confluentinc/kafka-javascript');
          const rows = await this.admin().fetchTopicOffsets(topic, {
            timeout: 2000,
            isolationLevel: library.KafkaJS.IsolationLevel.READ_UNCOMMITTED,
          });
          const row = rows.find((entry) => entry.partition === partition);
          if (!row) throw failure();
          const high = BigInt(offset(row.high)),
            lag = high - next;
          if (lag < 0n || lag > BigInt(Number.MAX_SAFE_INTEGER)) throw failure();
          this.observed.lag(this.config.name, topic, partition, lag);
        } catch {
          this.observed.event(this.config.name, 'lag-unavailable', topic);
        }
      })
      .finally(() => this.probes.delete(name));
    this.probes.set(name, probe);
  }

  producer(): KafkaJS.Producer<Buffer, Buffer> {
    if (!this.writer || this.closing) throw failure('EK_RESOURCE_CLOSED');
    return this.writer;
  }
  admin(): KafkaJS.Admin {
    if (!this.administrator || this.closing) throw failure('EK_RESOURCE_CLOSED');
    return this.administrator;
  }
  rebalanceKind(code: number | undefined): 'assign' | 'revoke' | 'error' {
    const library =
      require('@confluentinc/kafka-javascript') as typeof import('@confluentinc/kafka-javascript');
    if (code === library.KafkaJS.ErrorCodes.ERR__ASSIGN_PARTITIONS) return 'assign';
    if (code === library.KafkaJS.ErrorCodes.ERR__REVOKE_PARTITIONS) return 'revoke';
    return 'error';
  }
  consumer(
    groupId: string,
    offsetReset: 'earliest' | 'latest',
    rebalance: NonNullable<KafkaJS.ConsumerConstructorConfig['rebalance_cb']>,
  ): KafkaJS.Consumer<Buffer, Buffer> {
    if (!this.client || this.closing) throw failure('EK_RESOURCE_CLOSED');
    return this.client.consumer<Buffer, Buffer>({
      kafkaJS: {
        groupId,
        fromBeginning: offsetReset === 'earliest',
        autoCommit: false,
        allowAutoTopicCreation: false,
      },
      'enable.auto.commit': false,
      'group.protocol': 'classic',
      'max.poll.interval.ms': 30000,
      'session.timeout.ms': 10000,
      'heartbeat.interval.ms': 3000,
      'queued.min.messages': 1,
      'queued.max.messages.kbytes': Math.max(
        1,
        Math.ceil((this.config.maxBufferedMessages * (this.config.maxMessageBytes + 16384)) / 1024),
      ),
      'fetch.message.max.bytes': Math.max(1000, this.config.maxMessageBytes + 65536),
      'message.max.bytes': Math.max(1000, this.config.maxMessageBytes + 65536),
      'fetch.max.bytes': Math.max(1000, this.config.maxMessageBytes + 65536),
      'js.consumer.max.cache.messages': this.config.maxBufferedMessages,
      rebalance_cb: rebalance,
    });
  }
  close(): Promise<void> {
    return (this.closing ??= (async () => {
      // Signal the driver's bounded connection loop before waiting for its physical completion.
      if (this.connecting.size) {
        try {
          await this.writer?.disconnect();
        } catch {
          /* Final cleanup below reports persistent failure. */
        }
      }
      await Promise.allSettled([...this.connecting]);
      await Promise.allSettled([...this.probes.values()]);
      let failed = false;
      try {
        await this.administrator?.disconnect();
      } catch {
        failed = true;
      }
      try {
        await this.writer?.disconnect();
      } catch {
        failed = true;
      }
      if (failed) throw failure('EK_KAFKA_CONNECT');
    })());
  }
  private track(value: Promise<unknown>): void {
    this.connecting.add(value);
    const settled = () => this.connecting.delete(value);
    void value.then(settled, settled);
  }
}
