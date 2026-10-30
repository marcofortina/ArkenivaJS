// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { connect as connectTls } from 'node:tls';
import { createSocket } from 'node:dgram';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';

/** The actual client lives outside the server worker and never reports payload or endpoints. */
export async function exchangeSocket(input) {
  const { kind, size, marker, binding, caFile, wrongName = false } = input;
  assert.ok(['tcp', 'tls', 'udp', 'unix'].includes(kind));
  assert.ok([64, 256, 4096, 65536].includes(size));
  assert.equal(typeof marker, 'string');
  assert.ok(marker.length > 0 && marker.length < 128);
  if (kind === 'unix') assert.ok(binding.path?.startsWith('/tmp/arkenivajs-socket-comparison-'));
  else {
    assert.equal(binding.network.address, '127.0.0.1');
    assert.ok(
      Number.isInteger(binding.network.port) &&
        binding.network.port > 0 &&
        binding.network.port <= 65535,
    );
  }
  const payload = Buffer.alloc(size, marker);
  const options =
    kind === 'unix' ? { path: binding.path } : { host: '127.0.0.1', port: binding.network.port };
  const socket =
    kind === 'udp'
      ? createSocket('udp4')
      : kind === 'tls'
        ? connectTls({
            ...options,
            ca: await readFile(caFile),
            rejectUnauthorized: true,
            servername: wrongName ? 'wrong.invalid' : 'localhost',
            minVersion: 'TLSv1.2',
          })
        : connect(options);
  try {
    const started = performance.now();
    let firstByteMs;
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('The owned socket client timed out')), 3000);
      const fail = (cause) => {
        clearTimeout(timer);
        reject(cause);
      };
      socket.once('error', fail);
      const complete = (bytes, tls = undefined) => {
        try {
          assert.deepEqual(bytes, payload);
          clearTimeout(timer);
          resolve({
            receivedBytes: bytes.length,
            byteIdentityVerified: true,
            firstByteMs,
            exchangeElapsedMs: performance.now() - started,
            ...(tls ? { tls } : {}),
          });
        } catch (cause) {
          fail(cause);
        }
      };
      if (kind === 'udp') {
        socket.once('message', (bytes) => {
          firstByteMs = performance.now() - started;
          complete(bytes);
        });
        socket.send(payload, options.port, options.host, (cause) => {
          if (cause) fail(cause);
        });
      } else {
        const chunks = [];
        let bytes = 0;
        socket.on('data', (chunk) => {
          firstByteMs ??= performance.now() - started;
          bytes += chunk.length;
          if (bytes > size) fail(new Error('The owned echo exceeded its payload bound'));
          else chunks.push(chunk);
        });
        socket.once('end', () =>
          complete(
            Buffer.concat(chunks),
            kind === 'tls'
              ? { protocol: socket.getProtocol(), cipher: socket.getCipher().standardName }
              : undefined,
          ),
        );
        socket.once(kind === 'tls' ? 'secureConnect' : 'connect', () => socket.end(payload));
      }
    });
  } finally {
    if (kind === 'udp')
      await new Promise((done) => {
        try {
          socket.close(done);
        } catch {
          done();
        }
      });
    else socket.destroy();
  }
}

if (process.send)
  process.once('message', (input) => {
    void exchangeSocket(input).then(
      (result) => process.send({ ok: true, result }, () => process.disconnect()),
      () => process.send({ ok: false }, () => process.disconnect()),
    );
  });
