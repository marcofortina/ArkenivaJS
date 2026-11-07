// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import dgram from 'node:dgram';
import { EventEmitter, once } from 'node:events';
import { COMPONENTS, createApplication } from '@arkenivajs/core';
import type { Plugin, Telemetry } from '@arkenivajs/core';
import { socketPlugin, SOCKET_CAPABILITY } from '../../dist/index.js';
import type { SocketService } from '../../dist/index.js';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

test(
  'Independent UDP senders share bounded admission, preserve reply origins and recover after local overload',
  { timeout: 10000 },
  async () => {
    const changes = new EventEmitter(),
      deadline = AbortSignal.timeout(5000),
      first = gate(),
      second = gate(),
      clients = Array.from({ length: 9 }, () => dgram.createSocket('udp4')),
      payloads = clients.map((_, index) => Buffer.from([index, 101, 0, 255])),
      replies: { bytes: Buffer; port: number; address: string }[][] = clients.map(() => []),
      failures: unknown[] = [];
    let receivedBytes = 0,
      drops = 0,
      completed = 0,
      active = 0,
      maximumActive = 0;
    const admitted: { sender: number; port: number }[] = [];
    const changed = () => changes.emit('progress');
    // These public observer callbacks form barriers for actual native events, not send acknowledgements.
    const trace: Telemetry & { withoutScope<T>(work: () => T): T } = {
        withoutScope: (work) => work(),
        async measure(_name, work) {
          return work();
        },
        async withSpan(_name, work) {
          return work();
        },
        addCounter(name, value, attributes) {
          if (name === 'socket.payload.bytes' && attributes?.['socket.event'] === 'read')
            receivedBytes += value;
          if (name === 'socket.event.count' && attributes?.['socket.event'] === 'dropped')
            drops += value;
          changed();
        },
        recordHistogram(name) {
          if (name === 'socket.handler.duration.ms') completed++;
          changed();
        },
        setGauge() {},
        async flush() {},
      },
      observer: Plugin = {
        id: 'udp-pressure-observer',
        version: '1.0.0',
        capabilities: new Set(['telemetry']),
        init(context) {
          context.provide(COMPONENTS.telemetry, trace);
        },
        close() {},
      },
      app = await createApplication({
        service: { name: 'udp-many-senders', version: '1.0.0', environment: 'test' },
        plugins: [socketPlugin(), observer],
      });
    function waitFor(predicate: () => boolean): Promise<void> {
      return new Promise<void>((resolve, reject) => {
        const cleanup = () => {
            changes.off('progress', check);
            deadline.removeEventListener('abort', abort);
          },
          abort = () => {
            cleanup();
            reject(new Error('The bounded native UDP pressure fixture exceeded its deadline'));
          },
          check = () => {
            if (failures.length) {
              cleanup();
              reject(failures[0]);
            } else if (predicate()) {
              cleanup();
              resolve();
            }
          };
        changes.on('progress', check);
        deadline.addEventListener('abort', abort, { once: true });
        if (deadline.aborted) abort();
        else check();
      });
    }
    try {
      for (const [index, client] of clients.entries()) {
        client.on('error', (error) => {
          failures.push(error);
          changed();
        });
        client.on('message', (bytes, remote) => {
          replies[index]!.push({
            bytes: Buffer.from(bytes),
            port: remote.port,
            address: remote.address,
          });
          changed();
        });
        const listening = once(client, 'listening', { signal: deadline });
        client.bind(0, '127.0.0.1');
        await listening;
      }
      assert.equal(new Set(clients.map((client) => client.address().port)).size, clients.length);
      await app.start();
      const listener = app.resolve<SocketService>(SOCKET_CAPABILITY).createUdpServer(
        {
          name: 'global-pressure',
          family: 'udp4',
          host: '127.0.0.1',
          port: 0,
          maxConcurrentHandlers: 1,
          maxQueuedDatagrams: 1,
          maxDatagramBytes: 4,
          maxReplyBytes: 4,
          maxReplyAmplificationFactor: 1,
        },
        async (datagram, server) => {
          active++;
          maximumActive = Math.max(maximumActive, active);
          const sender = datagram.bytes[0]!;
          admitted.push({ sender, port: datagram.remote.port });
          changed();
          try {
            assert.deepEqual(Buffer.from(datagram.bytes), payloads[sender]);
            assert.equal(datagram.remote.port, clients[sender]!.address().port);
            if (sender === 0) await first.promise;
            if (sender === 1) await second.promise;
            await server.reply(datagram, datagram.bytes);
          } catch (error) {
            failures.push(error);
            throw error;
          } finally {
            active--;
            changed();
          }
        },
      );
      await listener.start();
      const port = listener.boundAddress!.network!.port;
      const send = async (index: number) => {
        await new Promise<void>((resolve, reject) => {
          clients[index]!.send(payloads[index]!, port, '127.0.0.1', (error) =>
            error ? reject(error) : resolve(),
          );
        });
      };
      await send(0);
      await waitFor(() => admitted.length === 1);
      await send(1);
      await waitFor(() => receivedBytes === 8);
      assert.equal(admitted.length, 1);
      assert.equal(drops, 0);

      await Promise.all([2, 3, 4, 5, 6, 7].map(send));
      await waitFor(() => drops === 6);
      assert.equal(receivedBytes, 32);
      assert.equal(listener.stats().receivedApplicationBytes, 32);
      assert.equal(listener.stats().droppedDatagrams, 6);
      assert.equal(admitted.length, 1);
      assert.equal(active, 1);
      // Eight observed datagrams minus six local drops and one started handler leaves one queued.
      assert.equal(receivedBytes / 4 - drops - admitted.length, 1);
      assert.ok(replies.every((values) => values.length === 0));

      first.release();
      await waitFor(() => admitted.length === 2 && replies[0]!.length === 1);
      assert.equal(active, 1);
      assert.equal(maximumActive, 1);
      assert.equal(replies[1]!.length, 0);
      second.release();
      await waitFor(() => completed === 2 && replies[1]!.length === 1);
      assert.equal(active, 0);

      await send(8);
      await waitFor(() => completed === 3 && replies[8]!.length === 1);
      await listener.stop({ timeoutMs: 1000 });
      assert.equal(listener.state, 'CLOSED');
      assert.equal(maximumActive, 1);
      assert.equal(active, 0);
      assert.deepEqual(
        admitted,
        [0, 1, 8].map((sender) => ({ sender, port: clients[sender]!.address().port })),
      );
      for (const [index, values] of replies.entries()) {
        assert.deepEqual(
          values,
          [0, 1, 8].includes(index) ? [{ bytes: payloads[index], port, address: '127.0.0.1' }] : [],
        );
      }
      assert.equal(listener.stats().receivedApplicationBytes, 36);
      assert.equal(listener.stats().sentApplicationBytes, 12);
      assert.equal(listener.stats().droppedDatagrams, 6);
      assert.equal(listener.stats().errors, 0);
      assert.deepEqual(failures, []);
    } finally {
      first.release();
      second.release();
      try {
        await app.stop({ timeoutMs: 1000 });
      } finally {
        await Promise.all(
          clients.map(async (client) => {
            try {
              await new Promise<void>((resolve) => client.close(resolve));
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== 'ERR_SOCKET_DGRAM_NOT_RUNNING')
                throw error;
            }
          }),
        );
      }
    }
  },
);
