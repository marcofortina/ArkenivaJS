// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import net from 'node:net';
import tls from 'node:tls';
import { randomUUID } from 'node:crypto';
import { lstat, chmod, realpath, unlink, mkdtemp, link, rmdir } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import type { BigIntStats } from 'node:fs';
import type { OperationOptions } from '@arkenivajs/core';
import { KitError } from '@arkenivajs/core';
import { withServerTls } from '@arkenivajs/core/support';
import type { SocketPeer, SocketPeerHandler, SocketServerBinding } from './contracts.js';
import { address, failure, operation } from './policy.js';
import type { Captured } from './policy.js';
import { counters, lifecycle } from './lifecycle.js';
import type { Observation } from './observation.js';
import { performance } from 'node:perf_hooks';

/** Stream I/O remains native; only owned buffers and pending writes are admitted here. */
export function streamServer(
  input: Captured,
  handler: SocketPeerHandler,
  observation: Observation,
) {
  if ('family' in input) throw failure('EK_SOCKET_CONFIG');
  const policy = input;
  const stats = counters(),
    connections = new Set<net.Socket>(),
    ownedSockets = new Set<net.Socket>(),
    handshakeKeys = new WeakMap<net.Socket, string>(),
    pendingHandshakes = new Map<string, { socket: net.Socket; began: number }>();
  const peerKey = (socket: net.Socket) =>
    `${socket.remoteFamily}/${socket.remoteAddress}/${socket.remotePort}`;
  const releaseConnection = (socket: net.Socket) => {
    ownedSockets.delete(socket);
    if (connections.delete(socket)) {
      stats.activeConnections--;
      observation.event(policy.kind, 'active', -1);
    }
    const key = handshakeKeys.get(socket);
    if (key && pendingHandshakes.get(key)?.socket === socket) pendingHandshakes.delete(key);
  };
  let server: net.Server | undefined,
    draining = false,
    owned: BigIntStats | undefined,
    closing: Promise<void> | undefined,
    privatePath: string | undefined,
    privateDirectory: string | undefined;
  const force = () => {
    draining = true;
    for (const socket of ownedSockets) socket.destroy();
    try {
      server?.close();
    } catch {
      /* A failed bind has no listener to close. */
    }
  };
  async function cleanPath() {
    if ('path' in policy && owned) {
      try {
        const current = await lstat(policy.path, { bigint: true });
        if (
          current.isSocket() &&
          current.dev === owned.dev &&
          current.ino === owned.ino &&
          current.uid === owned.uid
        )
          await unlink(policy.path);
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw failure('EK_SOCKET_IO');
      }
    }
    if (privateDirectory)
      try {
        await rmdir(privateDirectory);
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException).code !== 'ENOENT') throw failure('EK_SOCKET_IO');
      }
  }
  function accept(socket: net.Socket) {
    if (draining || socket.destroyed) return socket.destroy();
    const controller = new AbortController();
    let reader = false,
      pendingBytes = 0,
      pendingCount = 0,
      ending = false;
    const closed = () => {
      controller.abort();
    };
    socket.once('close', closed);
    socket.setTimeout(policy.idleTimeoutMs, () => {
      stats.errors++;
      observation.event(policy.kind, 'error', 1, 'timeout');
      socket.destroy();
    });
    let remote: SocketPeer['remote'];
    try {
      remote =
        socket.remoteAddress && socket.remotePort
          ? address({
              address: socket.remoteAddress,
              port: socket.remotePort,
              family: socket.remoteFamily,
            })
          : undefined;
    } catch {
      stats.errors++;
      socket.destroy();
      return;
    }
    function io(
      work: (done: (cause?: Error | null) => void) => void,
      input?: OperationOptions,
      bytes?: Uint8Array,
    ): Promise<void> {
      const options = operation(input, policy.shutdownTimeoutMs);
      const deadline = performance.now() + options.timeoutMs;
      if (options.signal?.aborted) return Promise.reject(failure('EK_ABORTED'));
      if (socket.destroyed || socket.writableEnded || (ending && bytes))
        return Promise.reject(failure('EK_SOCKET_CLOSED'));
      if (pendingCount >= 64 || pendingBytes + (bytes?.length ?? 0) > policy.maxPendingWriteBytes)
        return Promise.reject(failure('EK_SOCKET_CAPACITY'));
      pendingCount++;
      pendingBytes += bytes?.length ?? 0;
      observation.event(policy.kind, 'pending', bytes?.length ?? 0);
      return new Promise<void>((resolve, reject) => {
        let callback = false,
          drained = false,
          settled = false,
          accounted = false;
        const release = () => {
          if (accounted) return;
          accounted = true;
          pendingCount--;
          pendingBytes -= bytes?.length ?? 0;
          observation.event(policy.kind, 'pending', -(bytes?.length ?? 0));
        };
        const finish = (cause?: unknown) => {
          if (settled) return;
          if (cause === undefined && performance.now() >= deadline) {
            cause = failure('EK_TIMEOUT');
            socket.destroy();
          }
          settled = true;
          clearTimeout(timer);
          options.signal?.removeEventListener('abort', abort);
          socket.removeListener('close', onClose);
          socket.removeListener('drain', onDrain);
          if (cause) reject(cause);
          else resolve();
        };
        const onClose = () => {
            release();
            finish(failure('EK_SOCKET_CLOSED'));
          },
          abort = () => {
            socket.destroy();
            finish(failure('EK_ABORTED'));
          },
          onDrain = () => {
            drained = true;
            if (callback) {
              release();
              finish();
            }
          },
          timer = setTimeout(() => {
            socket.destroy();
            finish(failure('EK_TIMEOUT'));
          }, options.timeoutMs);
        options.signal?.addEventListener('abort', abort, { once: true });
        socket.once('close', onClose);
        try {
          if (bytes) {
            const accepted = socket.write(bytes, (error) => {
              callback = true;
              if (error) {
                release();
                finish(failure('EK_SOCKET_IO', error));
              } else {
                stats.sentApplicationBytes += bytes.length;
                observation.event(policy.kind, 'write', bytes.length);
                if (drained) {
                  release();
                  finish();
                }
              }
            });
            drained = accepted;
            if (!accepted) socket.once('drain', onDrain);
          } else {
            drained = true;
            work((error) => {
              release();
              finish(error ? failure('EK_SOCKET_IO') : undefined);
            });
          }
        } catch (cause) {
          release();
          finish(failure('EK_SOCKET_IO', cause));
        }
        if (options.signal?.aborted) abort();
      });
    }
    const peer: SocketPeer = Object.freeze({
      connectionId: randomUUID(),
      remote,
      signal: controller.signal,
      chunks() {
        if (reader) throw failure('EK_SOCKET_STATE');
        if (socket.destroyed) throw failure('EK_SOCKET_CLOSED');
        reader = true;
        const iterator = (async function* () {
          try {
            for await (const chunk of socket.iterator({ destroyOnReturn: false })) {
              stats.receivedApplicationBytes += chunk.length;
              observation.event(policy.kind, 'read', chunk.length);
              yield Uint8Array.from(chunk);
            }
          } catch {
            throw failure('EK_SOCKET_IO');
          } finally {
            if (!socket.readableEnded) socket.destroy();
          }
        })();
        let pulling = false,
          returning: Promise<IteratorResult<Uint8Array, void>> | undefined;
        const owned = {
          [Symbol.asyncIterator]() {
            return this;
          },
          next() {
            if (pulling) return Promise.reject(failure('EK_SOCKET_STATE'));
            pulling = true;
            return iterator.next().finally(() => {
              pulling = false;
            });
          },
          return() {
            // A generator's finally block does not run before its first next().
            socket.destroy();
            return (returning ??= iterator.return(undefined));
          },
          throw() {
            socket.destroy();
            return (returning ??= iterator.throw(failure('EK_SOCKET_IO')));
          },
        };
        return owned;
      },
      async send(data: Uint8Array, input?: OperationOptions) {
        if (!(data instanceof Uint8Array) || data.length > policy.maxPendingWriteBytes)
          throw failure('EK_SOCKET_CAPACITY');
        await io(() => undefined, input, Buffer.from(data));
      },
      async end(input?: OperationOptions) {
        operation(input, policy.shutdownTimeoutMs);
        if (ending) throw failure('EK_SOCKET_STATE');
        ending = true;
        await io((done) => socket.end(done), input);
      },
      close() {
        socket.destroy();
      },
    });
    const began = performance.now();
    let outcome: 'ok' | 'error' = 'ok';
    Promise.resolve()
      .then(() => observation.run(policy.kind, () => handler(peer)))
      .catch(() => {
        outcome = 'error';
        stats.errors++;
        observation.event(policy.kind, 'error', 1, 'error');
        socket.destroy();
      })
      .finally(() =>
        observation.duration(
          policy.kind,
          'handler',
          Math.max(0, performance.now() - began),
          outcome,
        ),
      );
  }
  const raw = (socket: net.Socket) => {
    if (draining || connections.size >= policy.maxConnections) {
      stats.rejectedConnections++;
      observation.event(policy.kind, 'rejected', 1, 'capacity');
      socket.destroy();
      return;
    }
    connections.add(socket);
    ownedSockets.add(socket);
    if (policy.kind === 'tls') {
      const key = peerKey(socket);
      handshakeKeys.set(socket, key);
      pendingHandshakes.set(key, { socket, began: performance.now() });
    }
    stats.acceptedConnections++;
    stats.activeConnections++;
    observation.event(policy.kind, 'connection');
    observation.event(policy.kind, 'active', 1);
    socket.on('error', () => {
      stats.errors++;
      observation.event(policy.kind, 'error', 1, 'error');
    });
    socket.once('close', () => {
      releaseConnection(socket);
    });
  };
  return lifecycle(policy.name, policy.kind, policy.shutdownTimeoutMs, stats, {
    async open(signal) {
      return observation
        .origin(async () => {
          if ('path' in policy) {
            if (process.platform === 'win32') throw failure('EK_UNSUPPORTED_CAPABILITY');
            const parent = dirname(policy.path),
              info = await lstat(parent);
            if (
              !info.isDirectory() ||
              info.isSymbolicLink() ||
              info.uid !== process.getuid?.() ||
              (info.mode & 0o077) !== 0 ||
              (await realpath(parent)) !== resolve(parent)
            )
              throw failure('EK_SOCKET_CONFIG');
            try {
              await lstat(policy.path);
              throw failure('EK_SOCKET_BIND');
            } catch (cause) {
              if ((cause as NodeJS.ErrnoException).code !== 'ENOENT')
                throw failure('EK_SOCKET_BIND');
            }
            if (Buffer.byteLength(join(parent, '.arkeniva-123456', 's')) > 103)
              throw failure('EK_SOCKET_CONFIG');
            privateDirectory = await mkdtemp(join(parent, '.arkeniva-'));
            await chmod(privateDirectory, 0o700);
            privatePath = join(privateDirectory, 's');
          }
          if ('tls' in policy && policy.tls) {
            try {
              server = await withServerTls(policy.tls, (options) =>
                tls.createServer(
                  {
                    ...options,
                    allowHalfOpen: true,
                    pauseOnConnect: false,
                    handshakeTimeout: policy.handshakeTimeoutMs,
                  },
                  (socket) => {
                    ownedSockets.add(socket);
                    socket.on('error', () => {
                      stats.errors++;
                      observation.event('tls', 'error', 1, 'error');
                    });
                    const pending = pendingHandshakes.get(peerKey(socket));
                    pendingHandshakes.delete(peerKey(socket));
                    if (pending)
                      observation.duration(
                        'tls',
                        'handshake',
                        Math.max(0, performance.now() - pending.began),
                        'ok',
                      );
                    socket.once('close', () => {
                      ownedSockets.delete(socket);
                      if (pending) releaseConnection(pending.socket);
                    });
                    socket.disableRenegotiation();
                    socket.pause();
                    accept(socket);
                  },
                ),
              );
            } catch (cause) {
              throw failure('EK_SOCKET_TLS_HANDSHAKE', cause);
            }
            server.on('tlsClientError', (_cause: Error, socket: tls.TLSSocket) => {
              stats.errors++;
              socket.destroy();
              const pending = pendingHandshakes.get(peerKey(socket));
              if (pending) {
                observation.duration(
                  'tls',
                  'handshake',
                  Math.max(0, performance.now() - pending.began),
                  'error',
                );
                releaseConnection(pending.socket);
              }
              observation.event('tls', 'handshake', 1, 'error');
            });
          } else server = net.createServer({ allowHalfOpen: true, pauseOnConnect: true }, accept);
          // Pending TLS handshakes count toward admission before secureConnection.
          server.prependListener('connection', raw);
          server.once('close', () => {
            void cleanPath().catch(() => {
              stats.errors++;
            });
          });
          let ready = false;
          server.on('error', () => {
            if (ready) stats.errors++;
          });
          return new Promise<SocketServerBinding>((resolve, reject) => {
            server!.once('error', (cause) => reject(failure('EK_SOCKET_BIND', cause)));
            server!.once('close', () => {
              if (!ready) reject(failure('EK_SOCKET_CLOSED'));
            });
            server!.once('listening', () => {
              void (async () => {
                if (signal.aborted || draining) {
                  force();
                  throw failure('EK_ABORTED');
                }
                if ('path' in policy) {
                  const before = await lstat(privatePath!, { bigint: true });
                  if (!before.isSocket() || before.uid !== BigInt(process.getuid!()))
                    throw failure('EK_SOCKET_BIND');
                  await chmod(privatePath!, policy.mode);
                  // The private bind path is removed before publication. Node's automatic
                  // unlink can therefore never target a replacement of the public path.
                  // link() publishes without overwriting a concurrently created endpoint.
                  await link(privatePath!, policy.path);
                  owned = before;
                  await unlink(privatePath!);
                  const after = await lstat(policy.path, { bigint: true });
                  if (
                    after.dev !== before.dev ||
                    after.ino !== before.ino ||
                    Number(after.mode & 0o777n) !== policy.mode
                  )
                    throw failure('EK_SOCKET_BIND');
                }
                if (signal.aborted || draining) {
                  force();
                  await cleanPath();
                  throw failure('EK_ABORTED');
                }
                ready = true;
                const native = server!.address();
                resolve(
                  Object.freeze(
                    typeof native === 'string'
                      ? { kind: policy.kind, path: 'path' in policy ? policy.path : native }
                      : { kind: policy.kind, network: address(native) },
                  ),
                );
              })().catch((cause) => {
                force();
                void cleanPath().catch(() => undefined);
                reject(cause);
              });
            });
            const options =
              'path' in policy
                ? { path: privatePath!, signal }
                : {
                    host: policy.host,
                    port: policy.port,
                    ipv6Only: policy.ipv6Only,
                    signal,
                    exclusive: true,
                  };
            try {
              server!.listen(options);
            } catch (cause) {
              reject(failure('EK_SOCKET_BIND', cause));
            }
          });
        })
        .catch((cause) => {
          if (cause instanceof KitError) throw cause;
          throw failure('EK_SOCKET_BIND', cause);
        });
    },
    async drain() {
      draining = true;
      // A connection without a completed TLS handshake owns no application work to drain.
      for (const pending of pendingHandshakes.values()) pending.socket.destroy();
      if (!closing)
        closing = (async () => {
          if (server)
            await new Promise<void>((resolve) => {
              server!.once('close', resolve);
              try {
                server!.close(() => resolve());
              } catch {
                resolve();
              }
            });
          await cleanPath();
        })();
      await closing;
    },
    force,
  });
}
