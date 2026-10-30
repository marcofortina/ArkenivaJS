// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import dgram from 'node:dgram';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createApplication, KitError } from '@arkenivajs/core';
import { socketPlugin, SOCKET_CAPABILITY } from '../../dist/index.js';
import type { SocketService, UdpDatagram } from '../../dist/index.js';

const code = (expected: string) => (cause: unknown) =>
  cause instanceof KitError && cause.code === expected;

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

async function until(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (predicate()) return;
    await delay(5);
  }
  assert.ok(predicate(), 'The owned native UDP endpoint did not reach its expected state');
}

async function send(socket: dgram.Socket, port: number, bytes: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.send(bytes, port, '127.0.0.1', (error) => (error ? reject(error) : resolve()));
  });
}

test(
  'UDP drain drops queued and newly arriving datagrams while its owned active reply completes before endpoint release',
  { timeout: 10000 },
  async () => {
    const app = await createApplication({
      service: { name: 'udp-drain-fixture', version: '1.0.0', environment: 'test' },
      plugins: [socketPlugin()],
    });
    const client = dgram.createSocket('udp4'),
      probe = dgram.createSocket('udp4'),
      replyAllowed = gate(),
      handlerMayFinish = gate(),
      replyAccepted = gate();
    let original: UdpDatagram | undefined,
      calls = 0,
      stopped = false,
      handlerError: unknown;
    const received: Buffer[] = [];
    client.on('message', (bytes) => received.push(Buffer.from(bytes)));
    try {
      await app.start();
      const clientListening = once(client, 'listening');
      client.bind(0, '127.0.0.1');
      await clientListening;
      const sockets = app.resolve<SocketService>(SOCKET_CAPABILITY),
        foreign = sockets.createUdpServer(
          { name: 'foreign', family: 'udp4', port: 0 },
          () => undefined,
        ),
        listener = sockets.createUdpServer(
          {
            name: 'draining',
            family: 'udp4',
            port: 0,
            maxConcurrentHandlers: 1,
            maxQueuedDatagrams: 1,
            maxReplyBytes: 8,
            maxReplyAmplificationFactor: 1,
          },
          async (datagram, server) => {
            calls++;
            original = datagram;
            try {
              await replyAllowed.promise;
              assert.equal(server.state, 'DRAINING');
              await assert.rejects(
                foreign.reply(datagram, datagram.bytes),
                code('EK_SOCKET_DATAGRAM'),
              );
              await assert.rejects(
                server.reply(datagram, Buffer.alloc(5)),
                code('EK_SOCKET_DATAGRAM'),
              );
              await server.reply(datagram, datagram.bytes);
              await assert.rejects(
                server.reply(datagram, Buffer.from('extra')),
                code('EK_SOCKET_DATAGRAM'),
              );
              replyAccepted.release();
              await handlerMayFinish.promise;
            } catch (error) {
              handlerError = error;
              replyAccepted.release();
              throw error;
            }
          },
        );
      await foreign.start();
      await listener.start();
      const port = listener.boundAddress!.network!.port,
        active = Buffer.from([1, 2, 3, 4]);
      await send(client, port, active);
      await until(() => calls === 1);
      await send(client, port, Buffer.from([5, 6, 7]));
      await until(() => listener.stats().receivedApplicationBytes === 7);
      assert.equal(listener.stats().droppedDatagrams, 0);
      assert.equal(calls, 1);

      const stopping = listener.stop({ timeoutMs: 2000 });
      void stopping.then(
        () => {
          stopped = true;
        },
        () => {
          stopped = true;
        },
      );
      await until(() => listener.stats().droppedDatagrams === 1);
      assert.equal(listener.state, 'DRAINING');
      assert.equal(stopped, false);
      await send(client, port, Buffer.from([8, 9]));
      await until(() => listener.stats().receivedApplicationBytes === 9);
      assert.equal(listener.stats().droppedDatagrams, 2);
      assert.equal(calls, 1);
      assert.equal(stopped, false);

      replyAllowed.release();
      await replyAccepted.promise;
      assert.equal(handlerError, undefined);
      await until(() => received.length === 1);
      assert.deepEqual(received, [active]);
      assert.equal(listener.stats().sentApplicationBytes, 4);
      assert.equal(foreign.stats().sentApplicationBytes, 0);
      assert.equal(listener.state, 'DRAINING');
      assert.equal(stopped, false);

      handlerMayFinish.release();
      await stopping;
      assert.equal(listener.state, 'CLOSED');
      assert.equal(stopped, true);
      assert.equal(calls, 1);
      assert.equal(listener.stats().errors, 0);
      await assert.rejects(listener.reply(original!, Buffer.alloc(0)), code('EK_SOCKET_DATAGRAM'));
      await listener.stop();
      assert.equal(listener.stats().droppedDatagrams, 2);

      const listening = once(probe, 'listening');
      probe.bind(port, '127.0.0.1');
      await listening;
      assert.equal(probe.address().port, port);
      assert.deepEqual(received, [active]);
    } finally {
      replyAllowed.release();
      handlerMayFinish.release();
      for (const socket of [client, probe]) {
        try {
          await new Promise<void>((resolve) => socket.close(resolve));
        } catch {
          /* A fixture that failed before bind owns no native endpoint. */
        }
      }
      await app.stop({ timeoutMs: 2000 });
    }
  },
);
