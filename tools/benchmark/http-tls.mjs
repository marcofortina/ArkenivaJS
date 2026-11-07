// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Agent, request } from 'node:https';
import { performance } from 'node:perf_hooks';
import { X509Certificate } from 'node:crypto';

const allowedErrors = new Set([
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
]);

/** One temporary identity is shared by the paired servers; trust remains process-local. */
export async function createHttpTlsFixture() {
  const directory = await mkdtemp('/tmp/arkenivajs-http-tls-');
  try {
    await chmod(directory, 0o700);
    const certificateFile = join(directory, 'server.pem'),
      privateKeyFile = join(directory, 'server.key'),
      caDirectory = join(directory, 'empty-ca-directory'),
      emptyCaFile = join(directory, 'empty-ca.pem'),
      optionsFile = join(directory, 'k6-options.json');
    await mkdir(caDirectory, { mode: 0o700 });
    await writeFile(emptyCaFile, '', { flag: 'wx', mode: 0o600 });
    await writeFile(optionsFile, '{}\n', { flag: 'wx', mode: 0o600 });
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=Owned HTTPS Comparison',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        privateKeyFile,
        '-out',
        certificateFile,
      ],
      { timeout: 10000, maxBuffer: 65536 },
    );
    await chmod(privateKeyFile, 0o600);
    return {
      certificateFile,
      privateKeyFile,
      caDirectory,
      emptyCaFile,
      optionsFile,
      close: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (cause) {
    await rm(directory, { recursive: true, force: true });
    throw cause;
  }
}

/** Owned HTTPS clients cannot inherit a global k6 configuration, proxy or verification bypass. */
export function httpTlsLoadEnvironment(environment, fixture, untrusted = false) {
  const result = { ...environment };
  for (const key of Object.keys(result))
    if (key.startsWith('K6_') || /^(?:https?|all|no)_proxy$/i.test(key)) delete result[key];
  return {
    ...result,
    SSL_CERT_FILE: untrusted ? fixture.emptyCaFile : fixture.certificateFile,
    SSL_CERT_DIR: fixture.caDirectory,
    GODEBUG: 'http2client=0',
    NO_PROXY: '*',
    K6_NO_USAGE_REPORT: 'true',
  };
}

/** These aggregate native observations contain no peer identity or certificate material. */
export function observeHttpsServer(server) {
  let counters;
  const reset = () => {
    counters = {
      successfulHandshakes: 0,
      resumedHandshakes: 0,
      handshakeErrors: 0,
      http11Requests: 0,
      unexpectedHttpVersions: 0,
      observerFailures: 0,
      tlsVersions: {},
      ciphers: {},
      alpn: {},
    };
  };
  reset();
  const add = (values, value) => {
    assert.ok(typeof value === 'string' && value.length > 0 && value.length <= 128);
    assert.ok(Object.hasOwn(values, value) || Object.keys(values).length < 16);
    values[value] = (values[value] ?? 0) + 1;
  };
  const secure = (socket) => {
    try {
      counters.successfulHandshakes++;
      if (socket.isSessionReused()) counters.resumedHandshakes++;
      add(counters.tlsVersions, socket.getProtocol());
      add(counters.ciphers, socket.getCipher().standardName);
      add(counters.alpn, socket.alpnProtocol || 'none');
    } catch {
      counters.observerFailures++;
    }
  };
  const failed = () => counters.handshakeErrors++;
  const received = (message) => {
    if (message.httpVersion === '1.1') counters.http11Requests++;
    else counters.unexpectedHttpVersions++;
  };
  server.on('secureConnection', secure);
  server.on('tlsClientError', failed);
  server.on('request', received);
  return {
    reset,
    snapshot: () => structuredClone(counters),
    close() {
      server.off('secureConnection', secure);
      server.off('tlsClientError', failed);
      server.off('request', received);
    },
  };
}

/** A connection-cold native control is independent of the Go load generator and server process. */
export async function probeHttpTls({
  origin,
  certificateFile,
  expectedBody,
  wrongName = false,
  untrusted = false,
}) {
  const endpoint = new URL(origin);
  assert.equal(endpoint.protocol, 'https:');
  assert.equal(endpoint.hostname, 'localhost');
  assert.equal(endpoint.origin, origin);
  assert.ok(
    Number.isInteger(Number(endpoint.port)) &&
      Number(endpoint.port) > 0 &&
      Number(endpoint.port) <= 65535,
  );
  assert.equal(Buffer.byteLength(expectedBody), 128);
  const ca = await readFile(certificateFile),
    expectedCertificate = new X509Certificate(ca);
  const agent = new Agent({ keepAlive: false, maxCachedSessions: 0 });
  let client;
  try {
    const started = performance.now();
    return await new Promise((resolve, reject) => {
      let connected, secured, firstByte, ended, socket, result, failure, handshake;
      const timer = setTimeout(
        () => client?.destroy(new Error('The owned HTTPS probe timed out')),
        5000,
      );
      const fail = (cause) => {
        clearTimeout(timer);
        const error = new Error('The owned HTTPS probe failed');
        if (allowedErrors.has(cause?.code)) error.code = cause.code;
        failure ??= error;
        if (socket) socket.destroy();
        else reject(failure);
      };
      client = request(new URL('/json', origin), {
        agent,
        ca: untrusted ? [] : ca,
        rejectUnauthorized: true,
        servername: wrongName ? 'wrong.invalid' : 'localhost',
        minVersion: 'TLSv1.3',
        ALPNProtocols: ['http/1.1'],
        family: 4,
        lookup: (_name, _options, callback) => callback(null, '127.0.0.1', 4),
      });
      client.once('error', fail);
      client.once('socket', (value) => {
        socket = value;
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
              peerCertificateRaw: socket.getPeerCertificate().raw,
            };
          } catch (cause) {
            fail(cause);
          }
        });
        socket.once('close', () => {
          clearTimeout(timer);
          if (failure) reject(failure);
          else if (result) resolve(result);
          else reject(new Error('The owned HTTPS probe failed'));
        });
      });
      client.once('response', (response) => {
        const chunks = [];
        let bytes = 0;
        response.on('error', fail);
        response.on('data', (chunk) => {
          firstByte ??= performance.now();
          bytes += chunk.length;
          if (bytes > 128) client.destroy(new Error('The owned HTTPS response exceeded its bound'));
          else chunks.push(chunk);
        });
        response.once('end', () => {
          ended = performance.now();
          try {
            assert.equal(response.statusCode, 200);
            assert.equal(response.httpVersion, '1.1');
            assert.equal(Buffer.concat(chunks).toString('utf8'), expectedBody);
            assert.equal(handshake.authorized, true);
            assert.equal(handshake.sessionReused, false);
            assert.equal(handshake.version, 'TLSv1.3');
            assert.equal(handshake.alpn, 'http/1.1');
            assert.equal(handshake.remoteAddress, '127.0.0.1');
            const certificate = new X509Certificate(handshake.peerCertificateRaw),
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
              role: 'independent-native-Node-control',
              status: 200,
              protocol: 'HTTP/1.1',
              responseBytes: bytes,
              byteIdentityVerified: true,
              physicalClientClosed: true,
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
          } catch (cause) {
            client.destroy(cause);
          }
        });
      });
      client.end();
    });
  } finally {
    client?.destroy();
    agent.destroy();
  }
}

export async function verifyHttpTlsServer(input) {
  const positive = await probeHttpTls(input);
  await assert.rejects(probeHttpTls({ ...input, wrongName: true }), {
    code: 'ERR_TLS_CERT_ALTNAME_INVALID',
  });
  await assert.rejects(probeHttpTls({ ...input, untrusted: true }), (cause) =>
    [
      'DEPTH_ZERO_SELF_SIGNED_CERT',
      'SELF_SIGNED_CERT_IN_CHAIN',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    ].includes(cause.code),
  );
  return {
    positive,
    wrongNameRejected: true,
    untrustedCaRejected: true,
    clientProcesses: 1,
    freshConnections: 3,
  };
}
