// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { mkdtemp, chmod, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, request, type ServerOptions } from 'node:https';
import {
  KitError,
  COMPONENTS,
  createApplication,
  type ServerTlsFiles,
  type HttpServerOptions,
  type Plugin,
} from '@arkenivajs/core';
import { createApi, apiPlugin, type ApiOptions } from '@arkenivajs/api';
import type { FastifyInstance } from 'fastify';
// Exercise the owned build artifact without adding a public export for the private adapter.
const { validateServerTlsFiles, withServerTls } = (await import(
  new URL('../../../dist/server-tls.js', import.meta.url).href
)) as typeof import('../../dist/server-tls.js');

const execute = promisify(execFile);
let directory: string,
  cert: string,
  key: string,
  otherCert: string,
  otherKey: string,
  encryptedKey: string;
const passphrase = randomBytes(32).toString('base64url');
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
const files = (): ServerTlsFiles => ({ certificateFile: cert, privateKeyFile: key });

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'arkenivajs-server-tls-'));
  await chmod(directory, 0o700);
  for (const prefix of ['server', 'other']) {
    await execute(
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
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        join(directory, prefix + '.key'),
        '-out',
        join(directory, prefix + '.pem'),
      ],
      { timeout: 10000 },
    );
    await chmod(join(directory, prefix + '.key'), 0o600);
  }
  cert = join(directory, 'server.pem');
  key = join(directory, 'server.key');
  otherCert = join(directory, 'other.pem');
  otherKey = join(directory, 'other.key');
  encryptedKey = join(directory, 'encrypted.key');
  await execute(
    'openssl',
    [
      'pkey',
      '-in',
      key,
      '-aes256',
      '-passout',
      'env:ARKENIVA_TLS_FIXTURE_PASSPHRASE',
      '-out',
      encryptedKey,
    ],
    { timeout: 10000, env: { ...process.env, ARKENIVA_TLS_FIXTURE_PASSPHRASE: passphrase } },
  );
  await chmod(encryptedKey, 0o600);
});
after(async () => {
  await rm(directory, { recursive: true, force: true });
});

async function exchange(options: ServerOptions, client: ServerOptions = {}) {
  let calls = 0;
  const server = createServer(options, (_req, reply) => {
    calls++;
    reply.end('secured');
  });
  server.on('tlsClientError', () => undefined);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const value = await new Promise<string>((resolve, reject) => {
      const outgoing = request(
        { hostname: '127.0.0.1', port: address.port, method: 'GET', ...client },
        (incoming) => {
          const bytes: Buffer[] = [];
          incoming.on('data', (part: Buffer) => bytes.push(part));
          incoming.once('end', () => resolve(Buffer.concat(bytes).toString()));
          incoming.once('error', reject);
        },
      );
      outgoing.setTimeout(2000, () => outgoing.destroy(new Error('TLS fixture timeout')));
      outgoing.once('error', reject);
      outgoing.end();
    });
    return { value, calls };
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('TLS file policy snapshots only explicit absolute references and rejects unsafe configuration before file access', () => {
  const input = { ...files(), minVersion: 'TLSv1.3' as const },
    captured = validateServerTlsFiles(input);
  input.certificateFile = '/changed';
  assert.equal(captured.certificateFile, cert);
  assert.equal(Object.isFrozen(captured), true);
  let invoked = false;
  const accessor = {
    ...files(),
    get caFile() {
      invoked = true;
      return cert;
    },
  };
  for (const value of [
    null,
    [],
    {},
    { ...files(), key: 'unexpected' },
    { ...files(), certificateFile: 'relative.pem' },
    { ...files(), privateKeyFile: '/tmp/null\0key' },
    { ...files(), caFile: null },
    { ...files(), minVersion: 'TLSv1.1' },
    { ...files(), clientCertificate: 'optional' },
    { ...files(), clientCertificate: 'required' },
    { ...files(), privateKeyPassphraseEnv: 'unsafe-name' },
    accessor,
  ])
    assert.throws(
      () => validateServerTlsFiles(value as ServerTlsFiles),
      code('EK_HTTP_TLS_CONFIG'),
    );
  assert.equal(invoked, false);
});

test('Bounded TLS files create a real trusted HTTPS context and clear temporary buffers after construction', async () => {
  let temporary: Buffer | undefined;
  const ca = await readFile(cert);
  const native = await withServerTls(files(), (options) => {
    temporary = options.key as Buffer;
    assert.equal(options.minVersion, 'TLSv1.2');
    assert.equal(options.requestCert, false);
    assert.equal(options.rejectUnauthorized, true);
    return createServer(options, (_req, reply) => reply.end('secured'));
  });
  assert.ok(temporary);
  assert.equal(
    temporary.every((byte) => byte === 0),
    true,
  );
  try {
    await new Promise<void>((resolve) => native.listen(0, '127.0.0.1', resolve));
    const address = native.address();
    assert.ok(address && typeof address === 'object');
    const result = await new Promise<string>((resolve, reject) => {
      const outgoing = request({ hostname: '127.0.0.1', port: address.port, ca }, (reply) => {
        const parts: Buffer[] = [];
        reply.on('data', (part: Buffer) => parts.push(part));
        reply.once('end', () => resolve(Buffer.concat(parts).toString()));
      });
      outgoing.once('error', reject);
      outgoing.end();
    });
    assert.equal(result, 'secured');
  } finally {
    native.closeAllConnections();
    await new Promise<void>((resolve) => native.close(() => resolve()));
  }
});

test('Required client certificates reject absent/untrusted clients and permit a trusted mutual handshake', async () => {
  const ca = await readFile(cert);
  for (const client of [
    { ca },
    { ca, cert: await readFile(otherCert), key: await readFile(otherKey) },
  ]) {
    await assert.rejects(
      withServerTls({ ...files(), caFile: cert, clientCertificate: 'required' }, (options) =>
        exchange(options, client),
      ),
    );
  }
  const clientKey = await readFile(key);
  try {
    const result = await withServerTls(
      { ...files(), caFile: cert, clientCertificate: 'required', minVersion: 'TLSv1.3' },
      (options) => exchange(options, { ca, cert: ca, key: clientKey }),
    );
    assert.deepEqual(result, { value: 'secured', calls: 1 });
  } finally {
    clientKey.fill(0);
  }
});

test('Missing, oversized, malformed, mixed, and mismatched key/certificate material never reaches the consumer', async () => {
  const malformed = join(directory, 'malformed.pem'),
    oversized = join(directory, 'oversized.pem'),
    mixed = join(directory, 'mixed.pem');
  await writeFile(malformed, 'not a certificate');
  await writeFile(oversized, Buffer.alloc(1048577));
  await writeFile(
    mixed,
    Buffer.concat([await readFile(cert), Buffer.from('\nunexpected trailing content')]),
  );
  const variants: ServerTlsFiles[] = [
    { ...files(), certificateFile: join(directory, 'missing.pem') },
    { ...files(), certificateFile: directory },
    { ...files(), certificateFile: malformed },
    { ...files(), certificateFile: oversized },
    { ...files(), certificateFile: mixed },
    { ...files(), privateKeyFile: malformed },
    { ...files(), privateKeyFile: otherKey },
    { ...files(), caFile: malformed },
  ];
  for (const value of variants) {
    let consumed = false;
    await assert.rejects(
      withServerTls(value, () => {
        consumed = true;
      }),
      (error) => {
        assert.equal(code('EK_HTTP_TLS_CERT')(error), true);
        assert.equal(JSON.stringify(error).includes(directory), false);
        assert.equal(JSON.stringify(error).includes('CERTIFICATE'), false);
        return true;
      },
    );
    assert.equal(consumed, false);
  }
});

test('Encrypted keys resolve only an explicit environment name and fail closed for missing/wrong passphrases', async () => {
  const name = 'ARKENIVA_SERVER_TLS_TEST_PASSPHRASE',
    previous = process.env[name];
  try {
    delete process.env[name];
    for (const value of [undefined, 'incorrect', passphrase]) {
      if (value !== undefined) process.env[name] = value;
      const operation = withServerTls(
        { ...files(), privateKeyFile: encryptedKey, privateKeyPassphraseEnv: name },
        () => 'loaded',
      );
      if (value === passphrase) assert.equal(await operation, 'loaded');
      else
        await assert.rejects(operation, (error) => {
          assert.equal(code('EK_HTTP_TLS_CERT')(error), true);
          assert.equal(JSON.stringify(error).includes(passphrase), false);
          return true;
        });
    }
    await assert.rejects(
      withServerTls({ ...files(), privateKeyFile: encryptedKey }, () => 'loaded'),
      code('EK_HTTP_TLS_CERT'),
    );
  } finally {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  }
});

test('Mounted secret symlinks resolve explicitly; failed consumers still clear all temporary material', async () => {
  const linked = join(directory, 'mounted-key');
  await symlink(key, linked);
  let retained: Buffer | undefined;
  await assert.rejects(
    withServerTls({ ...files(), privateKeyFile: linked }, (options) => {
      retained = options.key as Buffer;
      throw new Error('Owned native-context construction failed');
    }),
    code('EK_HTTP_TLS_CERT'),
  );
  assert.ok(retained);
  assert.equal(
    retained.every((byte) => byte === 0),
    true,
  );
});

test('Expired certificates and excessive chains fail before context construction', async () => {
  const expired = join(directory, 'expired.pem');
  await execute('openssl', ['x509', '-in', cert, '-signkey', key, '-days', '-1', '-out', expired], {
    timeout: 10000,
  });
  const excessive = join(directory, 'excessive.pem'),
    empty = join(directory, 'empty.pem');
  await writeFile(excessive, (await readFile(cert, 'utf8')).repeat(33));
  await writeFile(empty, '');
  for (const certificateFile of [expired, excessive, empty]) {
    let invoked = false;
    await assert.rejects(
      withServerTls({ ...files(), certificateFile }, () => {
        invoked = true;
      }),
      code('EK_HTTP_TLS_CERT'),
    );
    assert.equal(invoked, false);
  }
});

test(
  'Linux named pipes are rejected without waiting for a writer',
  { skip: process.platform !== 'linux' ? 'The named-pipe fixture requires Linux' : false },
  async () => {
    const pipe = join(directory, 'untrusted-pipe');
    await execute('mkfifo', ['-m', '600', pipe], { timeout: 5000 });
    await assert.rejects(
      withServerTls({ ...files(), privateKeyFile: pipe }, () => 'unexpected'),
      code('EK_HTTP_TLS_CERT'),
    );
  },
);

const service = { name: 'tls-application', version: '1.0.0', environment: 'test' as const };
function logging(): Plugin {
  const logger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    child() {
      return this;
    },
    setLevel() {},
    async flush() {},
  };
  return {
    id: 'logging',
    version: '1.0.0',
    capabilities: new Set(['logger']),
    init(context) {
      context.provide(COMPONENTS.logger, logger);
    },
    close() {},
  };
}
async function get(origin: string, ca?: Buffer, path = '/', client: ServerOptions = {}) {
  return await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const outgoing = request(
      new URL(path, origin),
      { ...(ca === undefined ? {} : { ca }), ...client },
      (reply) => {
        const parts: Buffer[] = [];
        reply.on('data', (part: Buffer) => parts.push(part));
        reply.once('end', () =>
          resolve({ status: reply.statusCode!, body: Buffer.concat(parts).toString() }),
        );
        reply.once('error', reject);
      },
    );
    outgoing.setTimeout(2000, () => outgoing.destroy(new Error('HTTPS fixture timeout')));
    outgoing.once('error', reject);
    outgoing.end();
  });
}

test('Application HTTPS file configuration preserves routing, OpenAPI, readiness and secret-reference redaction', async () => {
  const app = await createApplication({
    service,
    http: { protocol: 'https', host: '127.0.0.1', port: 0, tls: files() },
    plugins: [logging(), apiPlugin()],
  });
  app.api.get('/', {
    auth: { required: false },
    schema: {
      response: {
        type: 'object',
        properties: { secured: { type: 'boolean' } },
        required: ['secured'],
        additionalProperties: false,
      },
    },
    handler: () => ({ secured: true }),
  });
  assert.equal(
    (app.config.snapshot() as { http: { tls: { privateKeyFile: string } } }).http.tls
      .privateKeyFile,
    '[REDACTED]',
  );
  try {
    await app.start();
    const native = app.api.native() as FastifyInstance;
    const address = native.server.address();
    assert.ok(address && typeof address === 'object');
    const origin = `https://127.0.0.1:${address.port}`;
    const ca = await readFile(cert);
    assert.deepEqual(await get(origin, ca), { status: 200, body: '{"secured":true}' });
    assert.equal((await get(origin, ca, '/readyz')).status, 200);
    assert.equal(app.api.openApiDocument().openapi, '3.1.0');
    await assert.rejects(get(origin), /certificate|self-signed/i);
  } finally {
    await app.stop();
  }
});

test('HTTPS files resolve only on activation, and invalid material fails startup without opening HTTP', async () => {
  const api = createApi({
    service,
    protocol: 'https',
    port: 0,
    tls: { ...files(), certificateFile: join(directory, 'missing-at-start.pem') },
  });
  const native = api.native();
  assert.equal(native.server.listening, false);
  await assert.rejects(api.start(), code('EK_HTTP_TLS_CERT'));
  assert.equal(native.server.listening, false);
  await api.close();
});

test('HTTP and HTTPS discriminants reject ambiguity, insecure versions, unsupported HTTP2 and production port zero', async () => {
  for (const http of [
    { host: '127.0.0.1', port: 0, tls: files() },
    { protocol: 'http', host: '127.0.0.1', port: 0, tls: files() },
    { protocol: 'http', host: '127.0.0.1', port: 0, http2: false },
    { protocol: 'https', host: '127.0.0.1', port: 0 },
    { protocol: 'https', host: '127.0.0.1', port: 0, tls: { ...files(), minVersion: 'TLSv1.1' } },
  ])
    await assert.rejects(
      createApplication({
        service,
        http: http as HttpServerOptions,
        plugins: [logging(), apiPlugin()],
      }),
      code('EK_CONFIG_INVALID'),
    );
  for (const tls of [null, { key: 'wrong', cert: 'wrong', extra: true }])
    assert.throws(
      () => createApi({ service, tls } as unknown as ApiOptions),
      code('EK_HTTP_TLS_CONFIG'),
    );
  assert.throws(
    () => createApi({ service, protocol: 'http', tls: files() }),
    code('EK_HTTP_TLS_CONFIG'),
  );
  assert.throws(() => createApi({ service, protocol: 'https' }), code('EK_HTTP_TLS_CONFIG'));
  assert.throws(() => createApi({ service, http2: false }), code('EK_HTTP_TLS_CONFIG'));
  assert.throws(
    () => createApi({ service, tls: files(), http2: true }),
    code('EK_UNSUPPORTED_CAPABILITY'),
  );
  for (const environment of ['production', 'development'] as const) {
    await assert.rejects(
      createApplication({
        service: { ...service, environment },
        http: { host: '127.0.0.1', port: 0 },
        plugins: [logging(), apiPlugin()],
      }),
      code('EK_CONFIG_INVALID'),
    );
    assert.throws(
      () => createApi({ service: { ...service, environment }, port: 0 }),
      code('EK_HTTP_TLS_CONFIG'),
    );
  }
});

test('Explicit API registration without ApplicationOptions.http starts no implicit network listener', async () => {
  const app = await createApplication({ service, plugins: [logging(), apiPlugin()] });
  try {
    await app.start();
    const native = app.api.native() as FastifyInstance;
    assert.equal(native.server.listening, false);
    assert.equal(native.server.address(), null);
    assert.equal(app.state, 'READY');
    assert.equal(app.api.openApiDocument().openapi, '3.1.0');
  } finally {
    await app.stop();
  }
});

test('HTTPS bind failures retain a stable error and do not close another listener', async () => {
  const first = createApi({ service, port: 0, tls: files() });
  await first.start();
  const address = first.native().server.address();
  assert.ok(address && typeof address === 'object');
  const second = createApi({ service, port: address.port, tls: files() });
  const secondNative = second.native();
  try {
    await assert.rejects(second.start(), code('EK_HTTP_LISTEN'));
    assert.equal(first.native().server.listening, true);
    assert.equal(secondNative.server.listening, false);
  } finally {
    await second.close();
    await first.close();
  }
});

test('The managed HTTPS listener enforces configured client trust and minimum TLS before routes run', async () => {
  let calls = 0;
  const api = createApi({
    service,
    port: 0,
    tls: { ...files(), caFile: cert, clientCertificate: 'required', minVersion: 'TLSv1.3' },
  });
  api.get('/', {
    auth: { required: false },
    schema: {
      response: {
        type: 'object',
        properties: { secured: { type: 'boolean' } },
        required: ['secured'],
        additionalProperties: false,
      },
    },
    handler: () => {
      calls++;
      return { secured: true };
    },
  });
  const ca = await readFile(cert),
    clientKey = await readFile(key),
    foreignCert = await readFile(otherCert),
    foreignKey = await readFile(otherKey);
  try {
    await api.start();
    const origin = api.address();
    assert.ok(origin);
    await assert.rejects(get(origin, ca));
    await assert.rejects(get(origin, ca, '/', { cert: foreignCert, key: foreignKey }));
    await assert.rejects(get(origin, ca, '/', { cert: ca, key: clientKey, maxVersion: 'TLSv1.2' }));
    assert.equal(calls, 0);
    assert.equal((await get(origin, ca, '/', { cert: ca, key: clientKey })).status, 200);
    assert.equal(calls, 1);
  } finally {
    await api.close();
    clientKey.fill(0);
    foreignKey.fill(0);
  }
});

test('Legacy and explicit plain HTTP application settings remain equivalent', async () => {
  for (const protocol of [undefined, 'http'] as const) {
    const app = await createApplication({
      service,
      http: { ...(protocol === undefined ? {} : { protocol }), host: '127.0.0.1', port: 0 },
      plugins: [logging(), apiPlugin()],
    });
    try {
      await app.start();
      const native = app.api.native() as FastifyInstance;
      const address = native.server.address();
      assert.ok(address && typeof address === 'object');
      const result = await fetch(`http://127.0.0.1:${address.port}/livez`);
      assert.equal(result.status, 200);
    } finally {
      await app.stop();
    }
  }
});
