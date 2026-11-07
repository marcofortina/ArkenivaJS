// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { createServer as createTlsServer } from 'node:tls';
import { createSocket } from 'node:dgram';
import { fork } from 'node:child_process';
import { readFile, lstat, chmod } from 'node:fs/promises';
import { join } from 'node:path';

const sampledEchoes = new WeakMap();

/** A distinct listener isolates sampled byte counters from the transport verification corpus. */
export async function prepareSocketEcho(service, fixture) {
  assert.equal(sampledEchoes.has(service), false);
  const unix = fixture.sampleUnixEcho === true,
    tls = fixture.sampleTlsEcho === true,
    path = unix ? join(fixture.directory, 'sampled-unix4096.sock') : undefined;
  assert.ok(!unix || !tls);
  if (unix) await assert.rejects(lstat(path), { code: 'ENOENT' });
  const handle = service[unix ? 'createUnixServer' : tls ? 'createTlsServer' : 'createTcpServer'](
    unix
      ? { name: 'sampled-unix4096', path, mode: 0o600 }
      : tls
        ? {
            name: 'sampled-tls64',
            host: '127.0.0.1',
            port: 0,
            tls: {
              certificateFile: fixture.certificateFile,
              privateKeyFile: fixture.privateKeyFile,
              minVersion: 'TLSv1.3',
            },
          }
        : { name: 'sampled-tcp64', host: '127.0.0.1', port: 0 },
    async (peer) => {
      for await (const bytes of peer.chunks()) await peer.send(bytes);
      await peer.end();
    },
  );
  try {
    const binding = await handle.start();
    let identity;
    if (unix) {
      identity = await lstat(path, { bigint: true });
      assert.equal(identity.isSocket(), true);
      assert.equal(identity.isSymbolicLink(), false);
      assert.equal(identity.uid, BigInt(process.getuid()));
      assert.equal(identity.mode & 0o777n, 0o600n);
    }
    sampledEchoes.set(service, {
      handle,
      input: {
        kind: unix ? 'unix' : tls ? 'tls' : 'tcp',
        size: unix ? 4096 : 64,
        binding,
        marker: fixture.marker,
        ...(tls
          ? {
              caFile: fixture.certificateFile,
              sampleTls: true,
              minimumTlsVersion: 'TLSv1.3',
            }
          : {}),
      },
      operation: unix
        ? 'unix4096IndependentClient'
        : tls
          ? 'tls64IndependentClient'
          : 'tcp64IndependentClient',
      path,
      identity,
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
    async [state.operation]() {
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
    assert.equal(record.operation, state.operation);
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, 100);
    assert.equal(state.results.length, 120);
    for (const result of state.results) {
      assert.equal(result.receivedBytes, state.input.size);
      assert.equal(result.byteIdentityVerified, true);
      assert.ok(Number.isFinite(result.firstByteMs) && result.firstByteMs >= 0);
      assert.ok(
        Number.isFinite(result.exchangeElapsedMs) && result.exchangeElapsedMs >= result.firstByteMs,
      );
      if (state.input.kind === 'tls') {
        assert.equal(result.tls.protocol, 'TLSv1.3');
        assert.ok(typeof result.tls.cipher === 'string' && result.tls.cipher.length > 0);
        assert.equal(result.tls.authorized, true);
        assert.equal(result.tls.sessionReused, false);
        assert.equal(result.tls.certificateKeyType, 'ec');
        assert.equal(result.tls.certificateNamedCurve, 'prime256v1');
        assert.equal(result.tls.certificateKeyBits, 256);
        for (const name of [
          'tcpConnectElapsedMs',
          'handshakeElapsedMs',
          'firstByteFromConnectMs',
          'exchangeFromConnectMs',
          'payloadFirstByteMs',
          'payloadExchangeElapsedMs',
        ])
          assert.ok(Number.isFinite(result.tls[name]) && result.tls[name] >= 0);
        assert.ok(result.tls.firstByteFromConnectMs <= result.tls.exchangeFromConnectMs);
        assert.ok(result.tls.payloadFirstByteMs <= result.tls.payloadExchangeElapsedMs);
      }
    }
    if (state.identity) {
      const current = await lstat(state.path, { bigint: true });
      assert.equal(current.isSocket(), true);
      assert.equal(current.isSymbolicLink(), false);
      assert.equal(current.dev, state.identity.dev);
      assert.equal(current.ino, state.identity.ino);
      assert.equal(current.uid, state.identity.uid);
      assert.equal(current.mode & 0o777n, 0o600n);
    }
    await state.handle.stop();
    if (state.identity) await assert.rejects(lstat(state.path), { code: 'ENOENT' });
    const stats = state.handle.stats();
    assert.equal(stats.state, 'CLOSED');
    assert.equal(stats.acceptedConnections, 120);
    assert.equal(stats.receivedApplicationBytes, 120 * state.input.size);
    assert.equal(stats.sentApplicationBytes, 120 * state.input.size);
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
      ...(state.identity
        ? {
            sampledTransport: 'unix',
            sampledPayloadBytes: state.input.size,
            unixSocketOwned: true,
            unixSocketInodeStable: true,
            unixSocketMode: 0o600,
            unixPathRemoved: true,
          }
        : {}),
      ...(state.input.kind === 'tls'
        ? {
            sampledTransport: 'tls',
            sampledPayloadBytes: 64,
            completedAuthorizedTlsHandshakes: state.results.length,
            resumedTlsHandshakes: state.results.filter((value) => value.tls.sessionReused).length,
            observedTlsProtocols: [...new Set(state.results.map((value) => value.tls.protocol))],
            observedTlsCiphers: [...new Set(state.results.map((value) => value.tls.cipher))],
            tlsTimingOrigin: 'Before native TLS client construction, after reading its private CA',
            handshakeTimingWindow: 'Native TCP connect event through secureConnect',
          }
        : {}),
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
      if (failed || code !== 0 || message?.ok !== true) {
        const error = new Error('The independent owned socket client failed');
        if (message?.code === 'ERR_TLS_CERT_ALTNAME_INVALID')
          error.code = 'ERR_TLS_CERT_ALTNAME_INVALID';
        reject(error);
      } else resolve(message.result);
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
                    minVersion: options.tls.minVersion ?? 'TLSv1.2',
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
        if (kind === 'unix' && options.mode !== undefined) await chmod(options.path, options.mode);
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
  let clientProcessesWaited = 0,
    acceptedConnections = 0,
    receivedApplicationBytes = 0,
    sentApplicationBytes = 0;
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
      clientProcessesWaited++;
      if (kind === 'tls') {
        await assert.rejects(socketClient({ ...input, wrongName: true }), {
          code: 'ERR_TLS_CERT_ALTNAME_INVALID',
        });
        clientProcessesWaited++;
      }
      await handle.stop();
      const stats = handle.stats();
      assert.equal(stats.state, 'CLOSED');
      assert.equal(stats.receivedApplicationBytes, size);
      assert.equal(stats.sentApplicationBytes, size);
      if (kind !== 'udp') assert.equal(stats.acceptedConnections, kind === 'tls' ? 2 : 1);
      acceptedConnections += stats.acceptedConnections;
      receivedApplicationBytes += stats.receivedApplicationBytes;
      sentApplicationBytes += stats.sentApplicationBytes;
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
    ...(fixture.sampleUnixEcho || fixture.sampleTlsEcho
      ? {
          independentClientProcessesWaited: clientProcessesWaited,
          acceptedConnections,
          receivedApplicationBytes,
          sentApplicationBytes,
        }
      : {}),
  };
}
