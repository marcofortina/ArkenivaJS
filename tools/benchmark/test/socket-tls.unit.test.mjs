// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import {
  nativeSocket,
  prepareSocketEcho,
  socketEchoWorkload,
  completeSocketEcho,
  socketClient,
} from '../socket-workload.mjs';

async function fixture() {
  const directory = await mkdtemp('/tmp/arkenivajs-socket-comparison-'),
    certificateFile = join(directory, 'server.pem'),
    privateKeyFile = join(directory, 'server.key');
  try {
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
        '/CN=Owned Socket TLS Control',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        privateKeyFile,
        '-out',
        certificateFile,
      ],
      { timeout: 5000, maxBuffer: 65536 },
    );
    await chmod(privateKeyFile, 0o600);
    return {
      directory,
      certificateFile,
      privateKeyFile,
      marker: 'owned-tls-sampling-control',
      sampleTlsEcho: true,
      close: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (cause) {
    await rm(directory, { recursive: true, force: true });
    throw cause;
  }
}

test('Sampled TLS clients retain actual fresh handshake metadata and close their listener after incomplete evidence', async () => {
  const material = await fixture(),
    service = nativeSocket();
  try {
    await prepareSocketEcho(service, material);
    const callback = socketEchoWorkload(service).tls64IndependentClient,
      running = callback();
    await assert.rejects(callback());
    const result = await running;
    assert.equal(result.receivedBytes, 64);
    assert.equal(result.byteIdentityVerified, true);
    assert.equal(result.tls.protocol, 'TLSv1.3');
    assert.match(result.tls.cipher, /^TLS_/);
    assert.equal(result.tls.authorized, true);
    assert.equal(result.tls.sessionReused, false);
    assert.equal(result.tls.certificateKeyType, 'ec');
    assert.equal(result.tls.certificateNamedCurve, 'prime256v1');
    assert.equal(result.tls.certificateKeyBits, 256);
    assert.equal(result.tls.certificateKeyBitsSource, 'EC P-256 named curve');
    if (result.tls.ephemeralKeyInfo) {
      const ephemeral = result.tls.ephemeralKeyInfo;
      assert.equal(typeof ephemeral.type, 'string');
      if (ephemeral.name !== undefined) assert.equal(typeof ephemeral.name, 'string');
      if (ephemeral.size !== undefined)
        assert.ok(Number.isSafeInteger(ephemeral.size) && ephemeral.size > 0);
    }
    assert.ok(result.firstByteMs >= 0 && result.exchangeElapsedMs >= result.firstByteMs);
    for (const name of [
      'tcpConnectElapsedMs',
      'handshakeElapsedMs',
      'firstByteFromConnectMs',
      'exchangeFromConnectMs',
      'payloadFirstByteMs',
      'payloadExchangeElapsedMs',
    ])
      assert.ok(Number.isFinite(result.tls[name]) && result.tls[name] >= 0);
    assert.ok(result.tls.firstByteFromConnectMs >= result.tls.handshakeElapsedMs);
    assert.ok(result.tls.exchangeFromConnectMs >= result.tls.firstByteFromConnectMs);
    assert.ok(result.tls.payloadExchangeElapsedMs >= result.tls.payloadFirstByteMs);
    assert.doesNotMatch(JSON.stringify(result), /localhost|127\.0\.0\.1|server\.pem|server\.key/);
    await assert.rejects(completeSocketEcho(service, { measure: true, records: [] }));
    await assert.rejects(callback());
    assert.throws(() => socketEchoWorkload(service));
  } finally {
    await service.close();
    await material.close();
  }
});

test('The independent TLS hostname control reports only its native mismatch code and leaves legacy observations unchanged', async () => {
  const material = await fixture(),
    service = nativeSocket();
  const handle = service.createTlsServer({
    host: '127.0.0.1',
    port: 0,
    tls: {
      certificateFile: material.certificateFile,
      privateKeyFile: material.privateKeyFile,
      minVersion: 'TLSv1.2',
    },
  });
  try {
    const binding = await handle.start(),
      input = {
        kind: 'tls',
        size: 64,
        marker: material.marker,
        binding,
        caFile: material.certificateFile,
      },
      result = await socketClient(input);
    assert.equal(result.receivedBytes, 64);
    assert.equal(result.byteIdentityVerified, true);
    assert.deepEqual(Object.keys(result.tls).sort(), ['cipher', 'protocol']);
    await assert.rejects(socketClient({ ...input, wrongName: true }), (cause) => {
      assert.equal(cause.code, 'ERR_TLS_CERT_ALTNAME_INVALID');
      assert.equal(cause.message, 'The independent owned socket client failed');
      assert.doesNotMatch(JSON.stringify(cause), /wrong\.invalid|localhost|CERTIFICATE|server/);
      return true;
    });
    await handle.stop();
    const stats = handle.stats();
    assert.equal(stats.state, 'CLOSED');
    assert.equal(stats.acceptedConnections, 2);
    assert.equal(stats.receivedApplicationBytes, 64);
    assert.equal(stats.sentApplicationBytes, 64);
  } finally {
    await service.close();
    await material.close();
  }
});
