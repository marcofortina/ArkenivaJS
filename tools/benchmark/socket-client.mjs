// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { connect as connectTls } from 'node:tls';
import { createSocket } from 'node:dgram';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { X509Certificate } from 'node:crypto';

function tlsObservation(socket, { started, connected, secured, firstByte, completed }) {
  for (const instant of [started, connected, secured, firstByte, completed])
    assert.ok(Number.isFinite(instant));
  assert.ok(started <= connected && connected <= secured);
  assert.ok(secured <= firstByte && firstByte <= completed);
  assert.equal(socket.authorized, true);
  assert.equal(socket.isSessionReused(), false);
  assert.equal(socket.getProtocol(), 'TLSv1.3');
  const key = new X509Certificate(socket.getPeerCertificate().raw).publicKey;
  assert.equal(key.asymmetricKeyType, 'ec');
  assert.equal(key.asymmetricKeyDetails.namedCurve, 'prime256v1');
  const ephemeral = socket.getEphemeralKeyInfo();
  let ephemeralKeyInfo = null;
  if (ephemeral && Object.keys(ephemeral).length) {
    assert.ok(
      typeof ephemeral.type === 'string' &&
        ephemeral.type.length > 0 &&
        ephemeral.type.length <= 128,
    );
    ephemeralKeyInfo = { type: ephemeral.type };
    if (ephemeral.name !== undefined) {
      assert.ok(
        typeof ephemeral.name === 'string' &&
          ephemeral.name.length > 0 &&
          ephemeral.name.length <= 128,
      );
      ephemeralKeyInfo.name = ephemeral.name;
    }
    if (ephemeral.size !== undefined) {
      assert.ok(Number.isSafeInteger(ephemeral.size) && ephemeral.size > 0);
      ephemeralKeyInfo.size = ephemeral.size;
    }
  }
  return {
    authorized: true,
    sessionReused: false,
    certificateKeyType: key.asymmetricKeyType,
    certificateNamedCurve: key.asymmetricKeyDetails.namedCurve,
    certificateKeyBits: 256,
    certificateKeyBitsSource: 'EC P-256 named curve',
    ephemeralKeyInfo,
    tcpConnectElapsedMs: connected - started,
    handshakeElapsedMs: secured - connected,
    firstByteFromConnectMs: firstByte - started,
    exchangeFromConnectMs: completed - started,
    payloadFirstByteMs: firstByte - secured,
    payloadExchangeElapsedMs: completed - secured,
  };
}

/** The actual client lives outside the server worker and never reports payload or endpoints. */
export async function exchangeSocket(input) {
  const { kind, size, marker, binding, caFile, wrongName = false } = input;
  const sampleTls = input.sampleTls === true;
  assert.ok(['tcp', 'tls', 'udp', 'unix'].includes(kind));
  assert.ok([64, 256, 4096, 65536].includes(size));
  assert.equal(typeof marker, 'string');
  assert.ok(marker.length > 0 && marker.length < 128);
  if (sampleTls) {
    assert.equal(kind, 'tls');
    assert.equal(input.minimumTlsVersion, 'TLSv1.3');
  }
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
  const ca = kind === 'tls' ? await readFile(caFile) : undefined;
  const tlsStarted = sampleTls ? performance.now() : undefined;
  let connected, secured, firstPayload, completed;
  const socket =
    kind === 'udp'
      ? createSocket('udp4')
      : kind === 'tls'
        ? connectTls({
            ...options,
            ca,
            rejectUnauthorized: true,
            servername: wrongName ? 'wrong.invalid' : 'localhost',
            minVersion: input.minimumTlsVersion ?? 'TLSv1.2',
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
      if (sampleTls)
        socket.once('connect', () => {
          connected = performance.now();
        });
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
          if (sampleTls) firstPayload ??= performance.now();
          firstByteMs ??= performance.now() - started;
          bytes += chunk.length;
          if (bytes > size) fail(new Error('The owned echo exceeded its payload bound'));
          else chunks.push(chunk);
        });
        socket.once('end', () => {
          try {
            if (sampleTls) completed = performance.now();
            complete(
              Buffer.concat(chunks),
              kind === 'tls'
                ? {
                    protocol: socket.getProtocol(),
                    cipher: socket.getCipher().standardName,
                    ...(sampleTls
                      ? tlsObservation(socket, {
                          started: tlsStarted,
                          connected,
                          secured,
                          firstByte: firstPayload,
                          completed,
                        })
                      : {}),
                  }
                : undefined,
            );
          } catch (cause) {
            fail(cause);
          }
        });
        socket.once(kind === 'tls' ? 'secureConnect' : 'connect', () => {
          try {
            if (sampleTls) {
              secured = performance.now();
              assert.equal(socket.authorized, true);
              assert.equal(socket.isSessionReused(), false);
            }
            socket.end(payload);
          } catch (cause) {
            fail(cause);
          }
        });
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
      (cause) =>
        process.send(
          {
            ok: false,
            ...(cause?.code === 'ERR_TLS_CERT_ALTNAME_INVALID'
              ? { code: 'ERR_TLS_CERT_ALTNAME_INVALID' }
              : {}),
          },
          () => process.disconnect(),
        ),
    );
  });
