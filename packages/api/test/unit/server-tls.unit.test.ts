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
import { KitError, type ServerTlsFiles } from '@arkenivajs/core';
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
