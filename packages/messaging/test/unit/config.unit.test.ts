import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rootCertificates } from 'node:tls';
import { natsConfiguration, natsPolicy } from '../../dist/config.js';

const variable = 'ARKENIVA_NATS_CONFIGURATION_TEST';
test('NATS captures explicit TLS credentials, roots and subject namespace using public bounded SDK options', () => {
  const previous = process.env[variable];
  process.env[variable] = 'tls://scoped-user:private-password@localhost:4223?prefix=orders.alpha.';
  try {
    const policy = natsPolicy({ connectionStringEnv: variable, onError: async () => {} });
    assert.ok(Object.isFrozen(policy));
    assert.equal(natsPolicy({ onError: async () => {} }).connectionStringEnv, 'NATS_URL');
    const configuration = natsConfiguration(variable);
    assert.equal(configuration.prefix, 'orders.alpha.');
    assert.deepEqual(configuration.native.servers, ['tls://localhost:4223']);
    assert.equal(configuration.native.user, 'scoped-user');
    assert.equal(configuration.native.pass, 'private-password');
    assert.equal(configuration.native.tls?.handshakeFirst, true);
    assert.ok(configuration.native.tls?.ca);
    assert.equal(configuration.native.ignoreClusterUpdates, true);
    assert.equal(configuration.native.maxReconnectAttempts, 5);
    assert.equal(configuration.native.waitOnFirstConnect, false);
    assert.equal(configuration.native.debug, false);
    process.env[variable] = 'changed';
    assert.equal(configuration.native.user, 'scoped-user');
    assert.equal('pendingLimit' in configuration.native, false);
  } finally {
    if (previous === undefined) delete process.env[variable];
    else process.env[variable] = previous;
  }
});

test('NATS rejects malformed executable policy without invoking accessors or opening resources', () => {
  let reads = 0;
  const accessor = Object.defineProperty({}, 'onError', {
    get() {
      reads++;
      return async () => {};
    },
  });
  for (const input of [
    null,
    [],
    {},
    { onError: false },
    { onError: async () => {}, unknown: true },
    { onError: async () => {}, connectionStringEnv: 'bad-name' },
    accessor,
  ])
    assert.throws(() => natsPolicy(input as never), { code: 'EK_CONFIG_INVALID' });
  assert.equal(reads, 0);
});

test('NATS rejects plaintext, ambient trust bypass, ambiguous options and unscoped connection data', () => {
  const previous = process.env[variable],
    oldTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    delete process.env[variable];
    assert.throws(() => natsConfiguration(variable), { code: 'EK_CONFIG_MISSING' });
    for (const url of [
      'nats://user:password@localhost:4222?prefix=scope.',
      'tls://localhost:4222?prefix=scope.',
      'tls://user:password@localhost?prefix=scope.',
      'tls://user:password@localhost:4222',
      'tls://user:password@localhost:4222/path?prefix=scope.',
      'tls://user:password@localhost:4222?prefix=scope.&prefix=other.',
      'tls://user:password@localhost:4222?prefix=scope.&debug=true',
      'tls://user:password@localhost:4222?prefix=scope.&rejectUnauthorized=false',
      'tls://user:password@localhost:4222?prefix=*.foreign.',
      'tls://user:password@localhost:4222?prefix=no-dot',
      'tls://user:password@localhost:4222?prefix=scope.#fragment',
      'tls://user:password@localhost:4222?prefix=scope.\n',
      'tls://user:password@bad_host:4222?prefix=scope.',
      'tls://user:%0A@localhost:4222?prefix=scope.',
      'tls://user:password@localhost:4222?prefix=scope.&certFile=/missing',
      'tls://user:password@localhost:4222?prefix=scope.&caFile=relative.pem',
      'a'.repeat(65537),
    ]) {
      process.env[variable] = url;
      assert.throws(() => natsConfiguration(variable), { code: 'EK_CONFIG_INVALID' });
    }
    process.env[variable] = 'tls://user:password@localhost:4222?prefix=scope.';
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    assert.throws(() => natsConfiguration(variable), { code: 'EK_CONFIG_INVALID' });
  } finally {
    if (previous === undefined) delete process.env[variable];
    else process.env[variable] = previous;
    if (oldTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = oldTls;
  }
});

test('NATS TLS capture rejects nonregular, empty, oversized and publicly readable private key files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'nats-policy-')),
    path = join(directory, 'test.pem'),
    previous = process.env[variable];
  try {
    for (const content of ['', 'not PEM', 'x'.repeat(1048577)]) {
      await writeFile(path, content, { mode: 0o600 });
      const url = new URL('tls://user:password@localhost:4222?prefix=scope.');
      url.searchParams.set('caFile', path);
      process.env[variable] = url.href;
      assert.throws(() => natsConfiguration(variable), { code: 'EK_CONFIG_INVALID' });
    }
    const certificate = join(directory, 'certificate.pem');
    await writeFile(certificate, rootCertificates[0]!, { mode: 0o600 });
    await writeFile(path, 'invalid private data');
    await chmod(path, 0o644);
    const url = new URL('tls://user:password@localhost:4222?prefix=scope.');
    url.searchParams.set('keyFile', path);
    url.searchParams.set('certFile', certificate);
    process.env[variable] = url.href;
    assert.throws(() => natsConfiguration(variable), { code: 'EK_CONFIG_INVALID' });
    url.searchParams.delete('keyFile');
    url.searchParams.delete('certFile');
    url.searchParams.set('caFile', directory);
    process.env[variable] = url.href;
    assert.throws(() => natsConfiguration(variable), { code: 'EK_CONFIG_INVALID' });
  } finally {
    if (previous === undefined) delete process.env[variable];
    else process.env[variable] = previous;
    await rm(directory, { recursive: true });
  }
});
