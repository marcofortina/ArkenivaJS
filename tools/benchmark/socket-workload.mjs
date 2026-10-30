// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { createServer as createTlsServer } from 'node:tls';
import { createSocket } from 'node:dgram';
import { fork } from 'node:child_process';
import { readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';

const sampledEchoes = new WeakMap();

/** A distinct listener isolates sampled byte counters from the transport verification corpus. */
export async function prepareSocketEcho(service, fixture) {
  assert.equal(sampledEchoes.has(service), false);
  const handle = service.createTcpServer(
    { name: 'sampled-tcp64', host: '127.0.0.1', port: 0 },
    async (peer) => {
      for await (const bytes of peer.chunks()) await peer.send(bytes);
      await peer.end();
    },
  );
  try {
    const binding = await handle.start();
    sampledEchoes.set(service, {
      handle,
      input: { kind: 'tcp', size: 64, binding, marker: fixture.marker },
      results: [],
      active: false,
      closed: false,
    });
  } catch (cause) {
    await handle.stop();
    throw cause;
  }
}

export function socketEchoWorkload(service) {
  const state = sampledEchoes.get(service);
  assert.ok(state);
  return {
    async tcp64IndependentClient() {
      assert.equal(state.closed, false);
      assert.equal(state.active, false);
      assert.ok(state.results.length < 120);
      state.active = true;
      try {
        const result = await socketClient(state.input);
        state.results.push(result);
        return result;
      } finally {
        state.active = false;
      }
    },
  };
}

export async function completeSocketEcho(service, { measure, records }) {
  const state = sampledEchoes.get(service);
  try {
    if (!measure) {
      assert.equal(state, undefined);
      assert.deepEqual(records, []);
      return { sampledEchoes: 0, warmupEchoes: 0, checkedEchoes: 0 };
    }
    assert.ok(state);
    assert.equal(state.active, false);
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'tcp64IndependentClient');
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, 100);
    assert.equal(state.results.length, 120);
    for (const result of state.results) {
      assert.equal(result.receivedBytes, 64);
      assert.equal(result.byteIdentityVerified, true);
      assert.ok(Number.isFinite(result.firstByteMs) && result.firstByteMs >= 0);
      assert.ok(
        Number.isFinite(result.exchangeElapsedMs) && result.exchangeElapsedMs >= result.firstByteMs,
      );
    }
    await state.handle.stop();
    const stats = state.handle.stats();
    assert.equal(stats.state, 'CLOSED');
    assert.equal(stats.acceptedConnections, 120);
    assert.equal(stats.receivedApplicationBytes, 7680);
    assert.equal(stats.sentApplicationBytes, 7680);
    return {
      sampledEchoes: 100,
      warmupEchoes: 20,
      checkedEchoes: 120,
      independentClientProcessesWaited: 120,
      acceptedConnections: stats.acceptedConnections,
      receivedApplicationBytes: stats.receivedApplicationBytes,
      sentApplicationBytes: stats.sentApplicationBytes,
      measurements: [...state.results],
      maximumRetainedResults: 128,
      listenerClosed: true,
      opaqueKernelBufferBytes: null,
    };
  } finally {
    try {
      if (state) {
        state.closed = true;
        state.results.length = 0;
        await state.handle.stop();
      }
    } finally {
      sampledEchoes.delete(service);
    }
  }
}

export const socketCases = Object.freeze([
  ['tcp', 64],
  ['tcp', 65536],
  ['tls', 64],
  ['udp', 256],
  ['unix', 4096],
]);

export function socketClient(input) {
  return new Promise((resolve, reject) => {
    const child = fork(new URL('./socket-client.mjs', import.meta.url), [], {
      execPath: process.execPath,
      execArgv: ['--max-old-space-size=128'],
      env: { NODE_ENV: 'test' },
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
    });
    let message,
      failed = false;
    const timer = setTimeout(() => {
      failed = true;
      child.kill('SIGKILL');
    }, 5000);
    child.once('message', (value) => {
      message = value;
    });
    child.once('error', () => {
      failed = true;
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (failed || code !== 0 || message?.ok !== true)
        reject(new Error('The independent owned socket client failed'));
      else resolve(message.result);
    });
    child.send(input);
  });
}

/** Direct Node servers retain byte counters from actual I/O and await their owned handlers. */
export function nativeSocket() {
  const handles = [];
  function create(kind, options) {
    let server,
      binding,
      state = 'CREATED',
      received = 0,
      sent = 0,
      accepted = 0;
    const peers = new Set(),
      tasks = new Set(),
      failures = [];
    function own(work) {
      const task = work
        .catch((cause) => {
          failures.push(cause);
        })
        .finally(() => tasks.delete(task));
      tasks.add(task);
    }
    const handle = {
      async start() {
        if (kind === 'udp') {
          server = createSocket('udp4');
          server.on('message', (bytes, remote) =>
            own(
              (async () => {
                received += bytes.length;
                await new Promise((done, reject) =>
                  server.send(bytes, remote.port, remote.address, (cause) =>
                    cause ? reject(cause) : done(),
                  ),
                );
                sent += bytes.length;
              })(),
            ),
          );
        } else {
          const handler = (peer) => {
            peers.add(peer);
            own(
              (async () => {
                try {
                  for await (const bytes of peer) {
                    received += bytes.length;
                    await new Promise((done, reject) =>
                      peer.write(bytes, (cause) => (cause ? reject(cause) : done())),
                    );
                    sent += bytes.length;
                  }
                  peer.end();
                } finally {
                  peers.delete(peer);
                }
              })(),
            );
          };
          server =
            kind === 'tls'
              ? createTlsServer(
                  {
                    allowHalfOpen: true,
                    key: await readFile(options.tls.privateKeyFile),
                    cert: await readFile(options.tls.certificateFile),
                    minVersion: 'TLSv1.2',
                  },
                  handler,
                )
              : createServer({ allowHalfOpen: true }, handler);
          server.on('tlsClientError', (_cause, socket) => socket.destroy());
          server.on('connection', (socket) => {
            accepted++;
            peers.add(socket);
            socket.once('close', () => peers.delete(socket));
          });
        }
        server.on('error', (cause) => {
          failures.push(cause);
        });
        await new Promise((done, reject) => {
          server.once('error', reject);
          const target = kind === 'unix' ? { path: options.path } : { host: '127.0.0.1', port: 0 };
          if (kind === 'udp') server.bind({ address: '127.0.0.1', port: 0 }, done);
          else server.listen(target, done);
        });
        state = 'LISTENING';
        const address = server.address();
        binding = kind === 'unix' ? { kind, path: address } : { kind, network: address };
        return binding;
      },
      async stop() {
        if (state === 'CLOSED') return;
        if (server) {
          for (const peer of peers) peer.destroy();
          await new Promise((done, reject) =>
            server.close((cause) => (cause ? reject(cause) : done())),
          );
          await Promise.all([...tasks]);
        }
        state = 'CLOSED';
        assert.equal(failures.length, 0);
      },
      stats: () => ({
        state,
        receivedApplicationBytes: received,
        sentApplicationBytes: sent,
        acceptedConnections: accepted,
      }),
    };
    handles.push(handle);
    return handle;
  }
  return {
    createTcpServer: (options) => create('tcp', options),
    createTlsServer: (options) => create('tls', options),
    createUdpServer: (options) => create('udp', options),
    createUnixServer: (options) => create('unix', options),
    close: async () => {
      for (const handle of [...handles].reverse()) await handle.stop();
    },
  };
}

export async function verifySocket(service, fixture) {
  const results = [];
  for (const [kind, size] of socketCases) {
    const options = {
      name: kind + '-' + size,
      ...(kind === 'unix'
        ? { path: join(fixture.directory, 'echo.sock') }
        : { host: '127.0.0.1', port: 0 }),
      ...(kind === 'tls'
        ? {
            tls: {
              certificateFile: fixture.certificateFile,
              privateKeyFile: fixture.privateKeyFile,
              minVersion: 'TLSv1.2',
            },
          }
        : {}),
      ...(kind === 'udp' ? { family: 'udp4' } : {}),
    };
    const handler =
      kind === 'udp'
        ? async (datagram, server) => server.reply(datagram, datagram.bytes)
        : async (peer) => {
            for await (const bytes of peer.chunks()) await peer.send(bytes);
            await peer.end();
          };
    const method = {
      tcp: 'createTcpServer',
      tls: 'createTlsServer',
      udp: 'createUdpServer',
      unix: 'createUnixServer',
    }[kind];
    const handle = service[method](options, handler);
    try {
      const binding = await handle.start();
      const input = {
        kind,
        size,
        binding,
        marker: fixture.marker,
        caFile: fixture.certificateFile,
      };
      const observed = await socketClient(input);
      if (kind === 'tls') await assert.rejects(socketClient({ ...input, wrongName: true }));
      await handle.stop();
      const stats = handle.stats();
      assert.equal(stats.state, 'CLOSED');
      assert.equal(stats.receivedApplicationBytes, size);
      assert.equal(stats.sentApplicationBytes, size);
      if (kind !== 'udp') assert.equal(stats.acceptedConnections, kind === 'tls' ? 2 : 1);
      if (kind === 'unix') await assert.rejects(lstat(options.path), { code: 'ENOENT' });
      results.push({
        kind,
        payloadBytes: size,
        ...observed,
        serverBytesVerified: true,
        closed: true,
      });
    } finally {
      await handle.stop();
    }
  }
  return {
    independentClientProcess: true,
    scenarios: results,
    tlsWrongNameRejected: true,
    unixPathRemoved: true,
  };
}
