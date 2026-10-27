// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants } from 'node:fs';
import { open, lstat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import type { ChannelModel, ConfirmChannel, Message } from 'amqplib';
import type { AmqpPublishReceipt } from './contracts.js';
import type { ConnectionSettings, Settings } from './settings.js';
import { endpoint } from './settings.js';
import { protocolText } from './settings.js';
import { failure } from './validation.js';
import type { Task } from './operation.js';
import type { Model, Recovery } from './native.js';
import { guardMessages } from './native.js';

const require = createRequire(import.meta.url),
  amqp = require('amqplib') as typeof import('amqplib');
export interface Pending {
  readonly messageId: string;
  returned: boolean;
  finish(status: AmqpPublishReceipt['status']): void;
}
/** Native recovery recreates channels and subscriptions; it never replays submitted publications. */
export class Connection {
  recovery: Recovery | undefined;
  model: Model | undefined;
  producer: ConfirmChannel | undefined;
  readonly pending = new Map<string, Pending>();
  readonly opening = new Set<Promise<unknown>>();
  readonly models = new Set<Model>();
  readonly restored = new Set<() => Promise<void>>();
  stopped = false;
  brokerBlocked = false;
  writeBlocked = false;
  failedPolicy = false;
  constructor(
    readonly settings: Settings,
    readonly config: ConnectionSettings,
    readonly event: (name: 'connect' | 'disconnect' | 'reconnect' | 'policy') => void = () =>
      undefined,
  ) {}
  get available(): boolean {
    return (
      !this.stopped &&
      !!this.model &&
      !this.model.connection.stream.destroyed &&
      !!this.producer &&
      !this.failedPolicy
    );
  }
  reset(): void {
    this.model?.connection.stream.destroy(failure('EK_AMQP_CONNECT'));
  }
  halt(): void {
    this.failedPolicy = true;
    this.event('policy');
    void this.close();
  }
  async init(task: Task<unknown>): Promise<void> {
    let ca: Buffer | undefined;
    try {
      task.check();
      const secret = await task.wait(
          this.settings.resolveSecret(this.config.connectionUriSecretRef, {
            signal: task.controller.signal,
            timeoutMs: task.remaining(),
          }),
        ),
        fields = endpoint(secret);
      if (this.config.tlsCaFile) {
        const path = this.config.tlsCaFile,
          entry = await task.wait(lstat(path));
        if (!entry.isFile() || entry.isSymbolicLink()) throw failure('EK_AMQP_CONFIG');
        const file = await open(
          path,
          constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
        );
        try {
          const stat = await file.stat();
          task.check();
          if (!stat.isFile() || stat.size < 1 || stat.size > 256 * 1024 || stat.mode & 0o022)
            throw failure('EK_AMQP_CONFIG');
          ca = Buffer.alloc(stat.size);
          let offset = 0;
          while (offset < ca.length) {
            const result = await file.read(ca, offset, ca.length - offset, offset);
            task.check();
            if (!result.bytesRead) throw failure('EK_AMQP_CONFIG');
            offset += result.bytesRead;
          }
          const after = await file.stat();
          if (
            after.size !== stat.size ||
            after.mtimeMs !== stat.mtimeMs ||
            after.ctimeMs !== stat.ctimeMs
          )
            throw failure('EK_AMQP_CONFIG');
        } finally {
          await file.close();
        }
      }
      task.check();
      this.recovery = (await amqp.connect(fields, {
        ...(ca ? { ca: Buffer.from(ca) } : {}),
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        timeout: 10000,
        noDelay: true,
        recovery: {
          initialMaxRetries: 0,
          maxRetries: 8,
          initialDelay: 100,
          maxDelay: 5000,
          factor: 2,
          jitter: 0.2,
          waitForConnect: false,
          setup: async (model: ChannelModel) => this.#setup(model as Model),
        },
      })) as Recovery;
      this.recovery.on('error', () => undefined);
      this.recovery.on('handler-error', () => undefined);
      this.recovery.on('blocked', () => {
        this.brokerBlocked = true;
      });
      this.recovery.on('unblocked', () => {
        this.brokerBlocked = false;
      });
      this.recovery.on('disconnect', () => {
        this.model = undefined;
        this.producer = undefined;
        this.event('disconnect');
      });
      this.recovery.on('reconnect-scheduled', () => this.event('reconnect'));
      this.recovery.on('connect', (model) => {
        if (!this.stopped) {
          this.model = model as Model;
          this.event('connect');
        }
      });
      // Retain an in-flight native connection attempt even when native close returns before it settles.
      const core = this.recovery._core,
        openModel = core._openModel.bind(core);
      core._openModel = () => {
        const pending = openModel().then((model) => {
          this.#track(model);
          if (this.stopped) model.connection.stream.destroy(failure('EK_AMQP_CONNECT'));
          return model;
        });
        this.opening.add(pending);
        void pending.catch(() => undefined).finally(() => this.opening.delete(pending));
        return pending;
      };
      await task.wait(this.recovery.waitForConnect());
      if (!this.available) throw failure('EK_AMQP_CONNECT');
    } catch {
      await this.close();
      task.check();
      throw failure('EK_AMQP_CONNECT');
    } finally {
      ca?.fill(0);
    }
  }
  #track(model: Model): void {
    this.models.add(model);
    model.on('error', () => undefined);
    model.on('handler-error', () => undefined);
    model.connection.stream.once('close', () => this.models.delete(model));
  }
  async #setup(model: Model): Promise<void> {
    model.on('error', () => undefined);
    model.on('handler-error', () => undefined);
    if (this.stopped) throw failure('EK_RESOURCE_CLOSED');
    const channel = await model.createConfirmChannel({ highWaterMark: 16 });
    channel.on('error', () => undefined);
    channel.on('handler-error', () => undefined);
    guardMessages(channel, this.config.maxMessageBytes, () => this.halt());
    channel.on('return', (message: Message) => {
      try {
        const id = protocolText(message.properties.correlationId, 128),
          pending = this.pending.get(id);
        if (!pending) throw failure();
        pending.returned = true;
      } catch {
        this.halt();
      }
    });
    channel.on('close', () => {
      if (this.producer === channel) {
        this.producer = undefined;
        if (!this.stopped) this.reset();
      }
      for (const pending of [...this.pending.values()]) pending.finish('unknown');
    });
    channel.on('drain', () => {
      if (this.producer === channel) this.writeBlocked = false;
    });
    const deadline = setTimeout(
      () => model.connection.stream.destroy(failure('EK_AMQP_CONNECT')),
      10000,
    );
    try {
      for (const exchange of this.config.topology.exchanges) {
        if (this.stopped) throw failure('EK_RESOURCE_CLOSED');
        if (this.config.allowTopologyProvisioning)
          await channel.assertExchange(exchange.name, exchange.type, {
            durable: exchange.durable,
            autoDelete: false,
          });
        else await channel.checkExchange(exchange.name);
      }
      for (const queue of this.config.topology.queues) {
        if (this.stopped) throw failure('EK_RESOURCE_CLOSED');
        if (this.config.allowTopologyProvisioning)
          await channel.assertQueue(queue.name, {
            durable: queue.durable,
            autoDelete: false,
            exclusive: false,
          });
        else await channel.checkQueue(queue.name);
      }
      if (this.config.allowTopologyProvisioning)
        for (const binding of this.config.topology.bindings)
          await channel.bindQueue(
            binding.queue,
            binding.exchange,
            binding.routingKey,
            binding.arguments,
          );
      if (this.stopped) throw failure('EK_RESOURCE_CLOSED');
      this.model = model;
      this.producer = channel;
      this.writeBlocked = false;
      this.brokerBlocked = false;
      for (const restore of this.restored) await restore();
    } catch {
      await channel.close().catch(() => undefined);
      throw failure('EK_AMQP_CONNECT');
    } finally {
      clearTimeout(deadline);
    }
  }
  async close(): Promise<void> {
    this.stopped = true;
    this.model = undefined;
    this.producer = undefined;
    for (const pending of [...this.pending.values()]) pending.finish('unknown');
    const recovery = this.recovery;
    this.recovery = undefined;
    // Native close waits specifically for CloseOk; a hard reset may never invoke that callback.
    // Stop native recovery, handle its promise and acknowledge actual socket closure instead.
    void recovery?.close().catch(() => undefined);
    const closed: Promise<void>[] = [];
    const stop = () => {
      for (const model of this.models) {
        const stream = model.connection.stream;
        if (!stream.closed)
          closed.push(new Promise<void>((resolve) => stream.once('close', () => resolve())));
        stream.destroy(failure('EK_AMQP_CONNECT'));
      }
    };
    stop();
    await Promise.allSettled([...this.opening]);
    stop();
    await Promise.all(closed);
    this.models.clear();
  }
}
