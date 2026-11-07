// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:https';
import { readFile, stat, access, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  createHttpTlsFixture,
  httpTlsLoadEnvironment,
  observeHttpsServer,
  probeHttpTls,
  verifyHttpTlsServer,
} from '../http-tls.mjs';
import { parseHttpBenchmarkArguments } from '../http-policy.mjs';

const body = JSON.stringify({ ok: true, value: 7, padding: 'x'.repeat(94) });

async function listener(fixture, handler) {
  const server = createServer(
    {
      key: await readFile(fixture.privateKeyFile),
      cert: await readFile(fixture.certificateFile),
      minVersion: 'TLSv1.3',
    },
    handler,
  );
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { server, origin: 'https://localhost:' + server.address().port };
}

test('Owned HTTPS controls verify the exact certificate and reject native CA/SAN failures before a route runs', async () => {
  const fixture = await createHttpTlsFixture();
  let server,
    observations,
    connections = 0,
    nativeFailures = 0,
    requests = 0;
  try {
    assert.equal((await stat(fixture.privateKeyFile)).mode & 0o777, 0o600);
    const owned = await listener(fixture, (_request, reply) => {
      requests++;
      reply.end(body);
    });
    server = owned.server;
    server.on('connection', () => connections++);
    server.on('tlsClientError', () => nativeFailures++);
    observations = observeHttpsServer(server);
    const result = await verifyHttpTlsServer({
      origin: owned.origin,
      certificateFile: fixture.certificateFile,
      expectedBody: body,
    });
    await new Promise((resolve) => server.close(resolve));
    assert.equal(result.wrongNameRejected, true);
    assert.equal(result.untrustedCaRejected, true);
    assert.equal(result.positive.physicalClientClosed, true);
    assert.equal(result.positive.responseBytes, 128);
    assert.equal(result.positive.tls.authorized, true);
    assert.equal(result.positive.tls.sessionReused, false);
    assert.equal(result.positive.tls.version, 'TLSv1.3');
    assert.equal(result.positive.tls.alpn, 'http/1.1');
    assert.equal(result.positive.tls.certificateKeyType, 'ec');
    assert.equal(result.positive.tls.certificateNamedCurve, 'prime256v1');
    assert.equal(result.positive.tls.certificateKeyBits, 256);
    for (const value of Object.values(result.positive.timings))
      assert.ok(Number.isFinite(value) && value >= 0);
    const observed = observations.snapshot();
    assert.equal(observed.successfulHandshakes, 1);
    assert.equal(observed.resumedHandshakes, 0);
    assert.equal(connections, 3);
    assert.equal(requests, 1);
    assert.equal(observed.handshakeErrors, nativeFailures);
    assert.ok(nativeFailures <= 2);
    assert.equal(observed.http11Requests, 1);
    assert.equal(observed.unexpectedHttpVersions, 0);
    assert.equal(observed.observerFailures, 0);
    assert.deepEqual(observed.alpn, { 'http/1.1': 1 });
    assert.doesNotMatch(
      JSON.stringify(result),
      /localhost|127\.0\.0\.1|server\.pem|server\.key|CERTIFICATE/,
    );
  } finally {
    observations?.close();
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
    await fixture.close();
    await assert.rejects(access(fixture.privateKeyFile), { code: 'ENOENT' });
  }
});

test('Owned HTTPS probes reject corrupted and oversized response bodies while a subsequent healthy exchange still succeeds', async () => {
  const fixture = await createHttpTlsFixture();
  let mode = 'corrupted',
    server;
  try {
    const owned = await listener(fixture, (_request, reply) =>
      reply.end(mode === 'corrupted' ? 'z'.repeat(128) : mode === 'oversized' ? body + 'x' : body),
    );
    server = owned.server;
    const input = {
      origin: owned.origin,
      certificateFile: fixture.certificateFile,
      expectedBody: body,
    };
    await assert.rejects(probeHttpTls(input), { message: 'The owned HTTPS probe failed' });
    mode = 'oversized';
    await assert.rejects(probeHttpTls(input), { message: 'The owned HTTPS probe failed' });
    mode = 'healthy';
    assert.equal((await probeHttpTls(input)).byteIdentityVerified, true);
  } finally {
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
    await fixture.close();
  }
});

test('HTTPS load configuration owns its trust and protocol settings without mutating the inherited environment', async () => {
  const environment = {
      PATH: '/owned/bin',
      K6_INSECURE_SKIP_TLS_VERIFY: 'true',
      K6_CONFIG: '/foreign/config',
      HTTPS_PROXY: 'http://foreign.invalid',
      http_proxy: 'http://foreign.invalid',
      GODEBUG: 'foreign-debug',
      SSL_CERT_FILE: '/foreign/ca',
    },
    original = structuredClone(environment),
    fixture = {
      certificateFile: '/owned/ca',
      emptyCaFile: '/owned/empty',
      caDirectory: '/owned/empty-directory',
    },
    result = httpTlsLoadEnvironment(environment, fixture);
  assert.deepEqual(environment, original);
  assert.equal(result.K6_INSECURE_SKIP_TLS_VERIFY, undefined);
  assert.equal(result.K6_CONFIG, undefined);
  assert.equal(result.HTTPS_PROXY, undefined);
  assert.equal(result.http_proxy, undefined);
  assert.equal(result.SSL_CERT_FILE, fixture.certificateFile);
  assert.equal(result.SSL_CERT_DIR, fixture.caDirectory);
  assert.equal(result.GODEBUG, 'http2client=0');
  assert.equal(result.NO_PROXY, '*');
  assert.equal(
    httpTlsLoadEnvironment(environment, fixture, true).SSL_CERT_FILE,
    fixture.emptyCaFile,
  );
  await assert.rejects(
    probeHttpTls({
      origin: 'https://foreign.invalid:443',
      certificateFile: '/unread',
      expectedBody: body,
    }),
  );
});

test('HTTPS smoke is explicit and refuses an unmarked execution before fixture or report creation', async () => {
  assert.deepEqual(parseHttpBenchmarkArguments(['/owned/evidence', '--smoke-https']), {
    directory: '/owned/evidence',
    policy: 'smoke',
    transport: 'https',
  });
  const directory = await mkdtemp('/tmp/arkenivajs-http-tls-entry-');
  try {
    const output = join(directory, 'report'),
      result = spawnSync(
        process.execPath,
        [fileURLToPath(new URL('../http.mjs', import.meta.url)), output, '--smoke-https'],
        { env: { PATH: process.env.PATH }, encoding: 'utf8', timeout: 10000 },
      );
    assert.equal(result.error, undefined);
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(
      result.stderr,
      'The HTTP benchmark failed; inspect the protected external artifacts\n',
    );
    await assert.rejects(access(output), { code: 'ENOENT' });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
