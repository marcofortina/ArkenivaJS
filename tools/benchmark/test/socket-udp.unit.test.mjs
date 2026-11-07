// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createSocket } from 'node:dgram';
import {
  socketClient,
  nativeSocket,
  prepareSocketEcho,
  socketEchoWorkload,
  completeSocketEcho,
} from '../socket-workload.mjs';

async function bind(socket) {
  await new Promise((done, reject) => {
    socket.once('error', reject);
    socket.bind({ address: '127.0.0.1', port: 0 }, done);
  });
}

async function close(socket) {
  await new Promise((done) => socket.close(done));
}

test(
  'Independent UDP clients reject a correct payload from a foreign source, reject corruption and recover on a healthy exchange',
  { timeout: 15000 },
  async () => {
    const owned = createSocket('udp4'),
      foreign = createSocket('udp4'),
      failures = [];
    let mode = 'foreign',
      foreignRepliesCompleted = 0,
      ownedRepliesCompleted = 0;
    await bind(owned);
    await bind(foreign);
    owned.on('error', (cause) => failures.push(cause));
    foreign.on('error', (cause) => failures.push(cause));
    owned.on('message', (bytes, peer) => {
      assert.equal(bytes.length, 256);
      const reply = Buffer.from(bytes);
      if (mode === 'corrupt') reply[reply.length - 1] ^= 1;
      const server = mode === 'foreign' ? foreign : owned;
      server.send(reply, peer.port, peer.address, (cause) => {
        if (cause) failures.push(cause);
        else if (server === foreign) foreignRepliesCompleted++;
        else ownedRepliesCompleted++;
      });
    });
    const input = {
      kind: 'udp',
      size: 256,
      marker: 'owned-udp-peer-control',
      sampleUdp: true,
      binding: { network: owned.address() },
    };
    try {
      await assert.rejects(socketClient(input));
      assert.equal(foreignRepliesCompleted, 1);
      assert.equal(ownedRepliesCompleted, 0);
      mode = 'corrupt';
      await assert.rejects(socketClient(input));
      mode = 'healthy';
      const result = await socketClient(input);
      assert.equal(result.receivedBytes, 256);
      assert.equal(result.byteIdentityVerified, true);
      assert.deepEqual(result.udp, {
        datagramsSent: 1,
        repliesFromExpectedPeer: 1,
        ignoredForeignDatagrams: 0,
        peerTupleVerified: true,
      });
      assert.equal(ownedRepliesCompleted, 2);
      assert.deepEqual(failures, []);
    } finally {
      await close(owned);
      await close(foreign);
    }
  },
);

test('Sampled UDP256 echo waits for its actual client and retires after incomplete evidence', async () => {
  const service = nativeSocket(),
    createUdpServer = service.createUdpServer;
  let listener;
  service.createUdpServer = (...args) => (listener = createUdpServer(...args));
  try {
    await prepareSocketEcho(service, { marker: 'owned-udp-sampling-control', sampleUdpEcho: true });
    const callback = socketEchoWorkload(service).udp256IndependentClient,
      running = callback();
    await assert.rejects(callback());
    const result = await running;
    assert.equal(result.receivedBytes, 256);
    assert.equal(result.byteIdentityVerified, true);
    assert.equal(result.udp.datagramsSent, 1);
    assert.equal(result.udp.repliesFromExpectedPeer, 1);
    assert.equal(result.udp.peerTupleVerified, true);
    await assert.rejects(completeSocketEcho(service, { measure: true, records: [] }));
    const stats = listener.stats();
    assert.equal(stats.state, 'CLOSED');
    assert.equal(stats.droppedDatagrams, null);
    assert.equal(stats.applicationDropObservation, 'not-applicable-no-application-drop-queue');
    assert.equal(stats.errors, 0);
    await assert.rejects(callback());
    assert.throws(() => socketEchoWorkload(service));
  } finally {
    await service.close();
  }
});

test('UDP sampling rejects conflicting transport selectors before opening its listener', async () => {
  const service = nativeSocket();
  try {
    for (const other of ['sampleUnixEcho', 'sampleTlsEcho', 'sampleTcp64kEcho'])
      await assert.rejects(
        prepareSocketEcho(service, {
          directory: '/tmp/arkenivajs-socket-comparison-unused',
          sampleUdpEcho: true,
          [other]: true,
        }),
      );
    assert.throws(() => socketEchoWorkload(service));
  } finally {
    await service.close();
  }
});
