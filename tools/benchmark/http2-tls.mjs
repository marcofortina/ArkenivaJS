// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { connect, constants } from 'node:http2';
import { connect as connectTls } from 'node:tls';
import { readFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { X509Certificate } from 'node:crypto';
import { verifyHttpTlsServer } from './http-tls.mjs';

const safeCodes = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'ABORT_ERR',
]);

function safeFailure(cause) {
  const error = new Error('The owned HTTP2 probe failed');
  if (safeCodes.has(cause?.code)) error.code = cause.code;
  return error;
}

/** Native HTTP/2 owns framing and retirement; only fixed metadata leaves this connection-cold control. */
export async function probeHttp2Tls({
  origin,
  certificateFile,
  expectedBody,
  wrongName = false,
  untrusted = false,
  signal,
}) {
  let endpoint, ca, expectedCertificate;
  try {
    endpoint = new URL(origin);
    assert.equal(endpoint.protocol, 'https:');
    assert.equal(endpoint.hostname, 'localhost');
    assert.equal(endpoint.origin, origin);
    assert.ok(
      Number.isInteger(Number(endpoint.port)) &&
        Number(endpoint.port) > 0 &&
        Number(endpoint.port) <= 65535,
    );
    assert.equal(typeof expectedBody, 'string');
    assert.equal(Buffer.byteLength(expectedBody), 128);
    assert.ok(signal === undefined || signal instanceof AbortSignal);
    if (signal?.aborted) throw safeFailure({ code: 'ABORT_ERR' });
    ca = await readFile(certificateFile);
    expectedCertificate = new X509Certificate(ca);
    if (signal?.aborted) throw safeFailure({ code: 'ABORT_ERR' });
  } catch (cause) {
    throw safeFailure(cause);
  }
  const started = performance.now();
  return new Promise((resolve, reject) => {
    let session,
      socket,
      stream,
      connected,
      secured,
      firstByte,
      ended,
      handshake,
      result,
      failure,
      sessionClosed = false,
      socketClosed = false,
      streamClosed = true;
    const settle = () => {
      if (!sessionClosed || !socketClosed || !streamClosed) return;
      clearTimeout(timer);
      signal?.removeEventListener('abort', aborted);
      if (failure) reject(failure);
      else if (result)
        resolve({ ...result, streamClosed: true, sessionClosed: true, tlsSocketClosed: true });
      else reject(safeFailure());
    };
    const retire = (force) => {
      if (!session || session.destroyed) return;
      if (force || !stream || stream.destroyed) session.destroy();
      else {
        if (!stream.closed) stream.close(constants.NGHTTP2_CANCEL);
        session.close();
      }
    };
    const fail = (cause, force = false) => {
      failure ??= safeFailure(cause);
      retire(force);
    };
    const aborted = () => {
      failure ??= safeFailure({ code: 'ABORT_ERR' });
      if (stream) session.close();
      else retire(true);
    };
    const timer = setTimeout(() => fail(undefined, true), 5000);
    signal?.addEventListener('abort', aborted, { once: true });
    try {
      session = connect(origin, {
        maxSessionMemory: 1,
        maxHeaderListPairs: 32,
        maxReservedRemoteStreams: 0,
        settings: { enablePush: false, maxHeaderListSize: 4096 },
        createConnection() {
          socket = connectTls({
            host: '127.0.0.1',
            port: Number(endpoint.port),
            ca: untrusted ? [] : ca,
            rejectUnauthorized: true,
            servername: wrongName ? 'wrong.invalid' : 'localhost',
            minVersion: 'TLSv1.3',
            ALPNProtocols: ['h2'],
          });
          socket.once('connect', () => {
            connected = performance.now();
          });
          socket.once('secureConnect', () => {
            secured = performance.now();
            try {
              handshake = {
                authorized: socket.authorized,
                sessionReused: socket.isSessionReused(),
                version: socket.getProtocol(),
                cipher: socket.getCipher().standardName,
                alpn: socket.alpnProtocol,
                remoteAddress: socket.remoteAddress,
                certificateRaw: socket.getPeerCertificate().raw,
              };
            } catch (cause) {
              fail(cause, true);
            }
          });
          socket.on('error', (cause) => fail(cause, true));
          socket.once('close', () => {
            socketClosed = true;
            settle();
          });
          return socket;
        },
      });
      session.on('error', (cause) => fail(cause, true));
      session.once('close', () => {
        sessionClosed = true;
        settle();
      });
      session.on('stream', (pushed) => {
        pushed.on('error', () => {});
        pushed.close(constants.NGHTTP2_CANCEL);
        fail(undefined, true);
      });
      session.once('connect', () => {
        try {
          assert.equal(handshake.authorized, true);
          assert.equal(handshake.sessionReused, false);
          assert.equal(handshake.version, 'TLSv1.3');
          assert.equal(handshake.alpn, 'h2');
          assert.equal(handshake.remoteAddress, '127.0.0.1');
          if (signal?.aborted) {
            aborted();
            return;
          }
          stream = session.request({ ':method': 'GET', ':path': '/json' }, { signal });
          streamClosed = false;
          const chunks = [];
          let bytes = 0,
            status;
          stream.on('error', (cause) => fail(cause));
          stream.once('close', () => {
            streamClosed = true;
            if (!result && !failure) fail();
            settle();
          });
          stream.once('response', (headers) => {
            status = headers[':status'];
          });
          stream.on('data', (chunk) => {
            firstByte ??= performance.now();
            bytes += chunk.length;
            if (bytes > 128) fail();
            else chunks.push(chunk);
          });
          stream.once('end', () => {
            ended = performance.now();
            if (failure) return;
            try {
              assert.equal(status, 200);
              assert.equal(Buffer.concat(chunks).toString('utf8'), expectedBody);
              const certificate = new X509Certificate(handshake.certificateRaw),
                key = certificate.publicKey;
              assert.deepEqual(certificate.raw, expectedCertificate.raw);
              assert.equal(key.asymmetricKeyType, 'ec');
              assert.equal(key.asymmetricKeyDetails.namedCurve, 'prime256v1');
              assert.ok([started, connected, secured, firstByte, ended].every(Number.isFinite));
              assert.ok(
                started <= connected &&
                  connected <= secured &&
                  secured <= firstByte &&
                  firstByte <= ended,
              );
              result = {
                role: 'independent-native-Node-h2-control',
                status,
                protocol: 'HTTP/2.0',
                responseBytes: bytes,
                byteIdentityVerified: true,
                tls: {
                  authorized: true,
                  sessionReused: false,
                  version: handshake.version,
                  cipher: handshake.cipher,
                  alpn: handshake.alpn,
                  certificateKeyType: key.asymmetricKeyType,
                  certificateNamedCurve: key.asymmetricKeyDetails.namedCurve,
                  certificateKeyBits: 256,
                  certificateKeyBitsSource: 'EC P-256 named curve',
                },
                timings: {
                  tcpConnectMs: connected - started,
                  handshakeMs: secured - connected,
                  firstByteFromConnectMs: firstByte - started,
                  exchangeFromConnectMs: ended - started,
                  payloadFirstByteMs: firstByte - secured,
                  payloadExchangeMs: ended - secured,
                },
              };
              session.close();
            } catch (cause) {
              fail(cause);
            }
          });
          stream.end();
        } catch (cause) {
          fail(cause, true);
        }
      });
    } catch (cause) {
      failure ??= safeFailure(cause);
      sessionClosed = true;
      if (socket) socket.destroy();
      else socketClosed = true;
      settle();
    }
  });
}

/** Both negotiated protocols use the same owned listener, trust anchor and exact response. */
export async function verifySecureHttp2Server(input) {
  const http2 = await probeHttp2Tls(input),
    http1Fallback = await verifyHttpTlsServer(input);
  await assert.rejects(probeHttp2Tls({ ...input, wrongName: true }), {
    code: 'ERR_TLS_CERT_ALTNAME_INVALID',
  });
  await assert.rejects(probeHttp2Tls({ ...input, untrusted: true }), (cause) =>
    [
      'DEPTH_ZERO_SELF_SIGNED_CERT',
      'SELF_SIGNED_CERT_IN_CHAIN',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    ].includes(cause.code),
  );
  return {
    http2,
    http1Fallback,
    observedResponseProtocols: ['HTTP/2.0', 'HTTP/1.1'],
    http2WrongNameRejected: true,
    http2UntrustedCaRejected: true,
  };
}
