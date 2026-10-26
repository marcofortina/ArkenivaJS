// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  verify,
} from 'node:crypto';
import { createApplication, KitError } from '@arkenivajs/core';
import type { Application, OperationOptions } from '@arkenivajs/core';
import { CRYPTO_CAPABILITY, cryptoPlugin } from '@arkenivajs/security-crypto';
import type {
  CryptoPluginSettings,
  CryptoService,
  SecretProvider,
  SecretValue,
} from '@arkenivajs/security-crypto';
import fc from 'fast-check';
import { captureSettings, createRuntime } from '../../dist/runtime.js';

const service = { name: 'crypto-test', version: '1.0.0', environment: 'test' } as const;
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
function fixture() {
  const ed = generateKeyPairSync('ed25519'),
    ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const values = new Map<string, SecretValue>([
    ['encryption', { bytes: randomBytes(32), keyVersion: randomUUID() }],
    ['old-encryption', { bytes: randomBytes(32), keyVersion: randomUUID() }],
    ['hmac', { bytes: randomBytes(32), keyVersion: 'hmac-v1' }],
    ['ed', { bytes: ed.privateKey.export({ format: 'der', type: 'pkcs8' }), keyVersion: 'ed-v1' }],
    ['ec', { bytes: ec.privateKey.export({ format: 'der', type: 'pkcs8' }), keyVersion: 'ec-v1' }],
  ]);
  let calls = 0;
  const secrets: SecretProvider = {
    async get(reference) {
      calls++;
      const value = values.get(reference);
      if (!value) throw new Error('Private secret provider failure');
      return value;
    },
  };
  const settings: CryptoPluginSettings = {
    secrets,
    signingKeyRefs: ['hmac', 'ed', 'ec'],
    encryptionKeyRefs: ['encryption', 'old-encryption'],
    policy: { maxConcurrent: 4, timeoutMs: 1000 },
  };
  return { values, secrets, settings, ed, ec, calls: () => calls };
}
async function start(settings: CryptoPluginSettings) {
  const app = await createApplication({ service, plugins: [cryptoPlugin(settings)] });
  await app.start();
  return { app, crypto: app.resolve<CryptoService>(CRYPTO_CAPABILITY) };
}

test('EK-STD-SEC-009 authenticated envelopes preserve exact bytes and reject tampering without plaintext', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings);
  const plaintext = randomBytes(257),
    aad = Buffer.from('tenant-one:invoice'),
    original = Buffer.from(plaintext);
  try {
    const envelope = await crypto.encrypt(plaintext, 'encryption', aad);
    assert.equal(envelope.version, 1);
    assert.equal(envelope.algorithm, 'AES-256-GCM');
    assert.equal(envelope.keyId, f.values.get('encryption')!.keyVersion);
    assert.equal(envelope.nonce.length, 12);
    assert.equal(envelope.tag.length, 16);
    assert.deepEqual(await crypto.decrypt(envelope, 'encryption', aad), original);
    assert.deepEqual(plaintext, original);
    for (const name of ['nonce', 'ciphertext', 'tag'] as const) {
      const changed = Buffer.from(envelope[name]);
      changed[0] = changed[0]! ^ 1;
      await assert.rejects(
        crypto.decrypt({ ...envelope, [name]: changed }, 'encryption', aad),
        code('EK_CRYPTO_AUTH_FAILED'),
      );
    }
    await assert.rejects(
      crypto.decrypt(envelope, 'encryption', Buffer.from('tenant-two:invoice')),
      code('EK_CRYPTO_AUTH_FAILED'),
    );
    await assert.rejects(
      crypto.decrypt(envelope, 'old-encryption', aad),
      code('EK_CRYPTO_KEY_UNAVAILABLE'),
    );
    await assert.rejects(
      crypto.decrypt({ ...envelope, algorithm: 'AES-CBC' } as never, 'encryption', aad),
      code('EK_CRYPTO_FORMAT'),
    );
    await assert.rejects(
      crypto.decrypt({ ...envelope, version: 2 } as never, 'encryption', aad),
      code('EK_CRYPTO_FORMAT'),
    );
    const empty = await crypto.encrypt(Buffer.alloc(0), 'encryption');
    assert.deepEqual(await crypto.decrypt(empty, 'encryption'), Buffer.alloc(0));
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 native GCM interoperability includes the documented version and purpose binding', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings);
  try {
    const plaintext = Buffer.from('Native interoperability'),
      aad = Buffer.from('trusted-purpose');
    const envelope = await crypto.encrypt(plaintext, 'encryption', aad);
    const header = Buffer.from(JSON.stringify([1, 'AES-256-GCM', envelope.keyId])),
      lengths = Buffer.alloc(8);
    lengths.writeUInt32BE(header.length);
    lengths.writeUInt32BE(aad.length, 4);
    const native = createCipheriv(
      'aes-256-gcm',
      f.values.get('encryption')!.bytes,
      envelope.nonce,
      { authTagLength: 16 },
    );
    native.setAAD(Buffer.concat([lengths, header, aad]));
    assert.deepEqual(
      Buffer.concat([native.update(plaintext), native.final()]),
      envelope.ciphertext,
    );
    assert.deepEqual(native.getAuthTag(), envelope.tag);
    const sameBytes = f.values.get('encryption')!.bytes;
    f.values.set('encryption', { bytes: sameBytes, keyVersion: 'substituted-version' });
    await assert.rejects(
      crypto.decrypt({ ...envelope, keyId: 'substituted-version' }, 'encryption', aad),
      code('EK_CRYPTO_AUTH_FAILED'),
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 fresh nonces are unique and provider rotations retain only explicitly approved old versions', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings);
  try {
    const nonces = new Set<string>();
    for (let n = 0; n < 256; n++)
      nonces.add(
        Buffer.from((await crypto.encrypt(Buffer.from('one'), 'encryption')).nonce).toString('hex'),
      );
    assert.equal(nonces.size, 256);
    const previous = f.values.get('encryption')!,
      envelope = await crypto.encrypt(Buffer.from('retained'), 'encryption');
    f.values.set('old-encryption', previous);
    f.values.set('encryption', { bytes: randomBytes(32), keyVersion: randomUUID() });
    assert.notEqual(f.values.get('encryption')!.keyVersion, previous.keyVersion);
    await assert.rejects(crypto.decrypt(envelope, 'encryption'), code('EK_CRYPTO_KEY_UNAVAILABLE'));
    assert.equal(
      Buffer.from(await crypto.decrypt(envelope, 'old-encryption')).toString(),
      'retained',
    );
    f.values.delete('old-encryption');
    await assert.rejects(
      crypto.decrypt(envelope, 'old-encryption'),
      code('EK_CRYPTO_KEY_UNAVAILABLE'),
    );
    const before = f.calls();
    await assert.rejects(
      crypto.encrypt(Buffer.alloc(1), 'unapproved'),
      code('EK_CRYPTO_KEY_UNAVAILABLE'),
    );
    assert.equal(f.calls(), before);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 HMAC-SHA256 matches RFC 4231 cases 6 and 7 and compares full MACs', async () => {
  const f = fixture();
  // Public RFC 4231 section 4.7/4.8 test material, never an application credential.
  f.values.set('hmac', { bytes: Buffer.alloc(131, 0xaa), keyVersion: 'public-rfc4231' });
  const { app, crypto } = await start(f.settings);
  try {
    const cases = [
      [
        'Test Using Larger Than Block-Size Key - Hash Key First',
        '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
      ],
      [
        'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.',
        '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2',
      ],
    ];
    for (const [text, expected] of cases) {
      const input = Buffer.from(text!),
        mac = await crypto.hmac(input, 'hmac');
      assert.equal(Buffer.from(mac).toString('hex'), expected);
      assert.equal(await crypto.verifyMac(input, mac, 'hmac'), true);
      assert.equal(
        await crypto.verifyMac(Buffer.concat([input, Buffer.from('changed')]), mac, 'hmac'),
        false,
      );
    }
    await assert.rejects(
      crypto.verifyMac(Buffer.alloc(0), Buffer.alloc(31), 'hmac'),
      code('EK_CRYPTO_FORMAT'),
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 Ed25519 and P-256 signatures interoperate with native verification without fallback', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings),
    input = randomBytes(64);
  try {
    for (const [reference, pair, algorithm] of [
      ['ed', f.ed, null],
      ['ec', f.ec, 'sha256'],
    ] as const) {
      const signature = await crypto.sign(input, reference),
        publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
      assert.equal(signature.length, 64);
      assert.equal(
        verify(algorithm, input, { key: pair.publicKey, dsaEncoding: 'ieee-p1363' }, signature),
        true,
      );
      assert.equal(await crypto.verifySignature(input, signature, publicKey), true);
      const native = sign(algorithm, input, { key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
      assert.equal(await crypto.verifySignature(input, native, publicKey), true);
      const changed = Buffer.from(signature);
      changed[0] = changed[0]! ^ 1;
      assert.equal(await crypto.verifySignature(input, changed, publicKey), false);
    }
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    f.values.set('ed', {
      bytes: rsa.privateKey.export({ format: 'der', type: 'pkcs8' }),
      keyVersion: 'unsupported-rsa',
    });
    await assert.rejects(crypto.sign(input, 'ed'), code('EK_CRYPTO_FORMAT'));
    await assert.rejects(
      crypto.verifySignature(
        input,
        Buffer.alloc(64),
        rsa.publicKey.export({ format: 'der', type: 'spki' }),
      ),
      code('EK_CRYPTO_FORMAT'),
    );
    await assert.rejects(crypto.sign(input, 'hmac'), code('EK_CRYPTO_FORMAT'));
    await assert.rejects(
      crypto.verifySignature(input, Buffer.alloc(64), Buffer.alloc(0)),
      code('EK_CRYPTO_FORMAT'),
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 factories reject unknown/null/accessor configuration without provider I/O', () => {
  const f = fixture();
  let invoked = 0;
  const getter = Object.defineProperty({}, 'secrets', {
    get() {
      invoked++;
      return f.secrets;
    },
    enumerable: true,
  });
  for (const settings of [
    null,
    undefined,
    {},
    getter,
    { ...f.settings, unknown: true },
    { ...f.settings, policy: null },
    { ...f.settings, policy: { maxConcurrent: 1, timeoutMs: 0 } },
    { ...f.settings, policy: { maxConcurrent: 1.5, timeoutMs: 1 } },
    { ...f.settings, policy: { maxConcurrent: 1025, timeoutMs: 1 } },
    { ...f.settings, policy: { maxConcurrent: 1024, timeoutMs: 1 } },
    { ...f.settings, policy: { maxConcurrent: 1, timeoutMs: 120001 } },
    { ...f.settings, encryptionKeyRefs: ['same', 'same'] },
    { ...f.settings, signingKeyRefs: [], encryptionKeyRefs: [] },
    { ...f.settings, secrets: { get: 1 } },
    { ...f.settings, secrets: {} },
    { ...f.settings, signingKeyRefs: ['bad reference'] },
    { ...f.settings, encryptionKeyRefs: new Array(1) },
  ])
    assert.throws(() => cryptoPlugin(settings as CryptoPluginSettings), code('EK_CONFIG_INVALID'));
  assert.equal(invoked, 0);
  assert.equal(f.calls(), 0);
});
test('EK-STD-SEC-009 malformed operations and byte budgets reject before any external key lookup', async () => {
  const f = fixture(),
    { app, crypto } = await start({
      ...f.settings,
      policy: { maxConcurrent: 1, timeoutMs: 1000, maxInputBytes: 64, maxOutputBytes: 64 },
    });
  try {
    const before = f.calls(),
      controller = new AbortController();
    controller.abort();
    for (const options of [
      null,
      { timeoutMs: 0 },
      { timeoutMs: 1.2 },
      { timeoutMs: 1001 },
      { timeoutMs: Infinity },
      { signal: {} },
      { unknown: true },
    ])
      await assert.rejects(
        crypto.hmac(Buffer.alloc(1), 'hmac', options as never),
        code('EK_CONFIG_INVALID'),
      );
    await assert.rejects(
      crypto.hmac(Buffer.alloc(1), 'hmac', { signal: controller.signal }),
      code('EK_ABORTED'),
    );
    await assert.rejects(crypto.hmac(Buffer.alloc(65), 'hmac'), code('EK_CRYPTO_FORMAT'));
    await assert.rejects(crypto.encrypt(Buffer.alloc(37), 'encryption'), code('EK_CRYPTO_FORMAT'));
    await assert.rejects(
      crypto.encrypt(Buffer.alloc(32), 'encryption', Buffer.alloc(33)),
      code('EK_CRYPTO_FORMAT'),
    );
    await assert.rejects(
      crypto.hmac(new Uint8Array(new SharedArrayBuffer(8)), 'hmac'),
      code('EK_CRYPTO_FORMAT'),
    );
    await assert.rejects(
      crypto.decrypt(
        {
          version: 1,
          algorithm: 'AES-256-GCM',
          keyId: 'v',
          nonce: Buffer.alloc(11),
          ciphertext: Buffer.alloc(0),
          tag: Buffer.alloc(16),
        },
        'encryption',
      ),
      code('EK_CRYPTO_FORMAT'),
    );
    assert.equal(f.calls(), before);
    await assert.rejects(crypto.hmac('not-bytes' as never, 'hmac'), code('EK_CRYPTO_FORMAT'));
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 provider failures, expiry and invalid material fail closed with no private diagnostics', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings);
  try {
    for (const value of [
      undefined,
      { bytes: randomBytes(31), keyVersion: 'short' },
      { bytes: randomBytes(33), keyVersion: 'wrong-aes' },
      { bytes: randomBytes(32), keyVersion: '' },
      { bytes: randomBytes(32), keyVersion: 'expired', expiresAt: new Date(0).toISOString() },
      { bytes: randomBytes(32), keyVersion: 'bad-expiry', expiresAt: 'tomorrow' },
      { bytes: randomBytes(32), keyVersion: 'extra', extra: true },
    ]) {
      if (value) f.values.set('encryption', value);
      else f.values.delete('encryption');
      await assert.rejects(
        crypto.encrypt(Buffer.from('private-plaintext'), 'encryption'),
        (error) => {
          assert.ok(code('EK_CRYPTO_KEY_UNAVAILABLE')(error));
          assert.ok(error instanceof KitError);
          assert.equal(error.cause, undefined);
          assert.equal(JSON.stringify(error).includes('private'), false);
          return true;
        },
      );
    }
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 provider class receivers and native byte snapshots cannot be replaced by caller hooks', async () => {
  const f = fixture();
  class Provider implements SecretProvider {
    readonly values = f.values;
    async get(reference: string) {
      return this.values.get(reference)!;
    }
  }
  const provider = new Provider(),
    plugin = cryptoPlugin({ ...f.settings, secrets: provider });
  provider.get = async () => {
    throw new Error('Replaced provider method');
  };
  const app = await createApplication({ service, plugins: [plugin] });
  await app.start();
  const crypto = app.resolve<CryptoService>(CRYPTO_CAPABILITY);
  let invoked = 0;
  const input = Buffer.from('real input');
  Object.defineProperty(input, Symbol.iterator, {
    value: () => {
      invoked++;
      throw new Error('Unexpected iterator');
    },
  });
  Object.defineProperty(input, 'byteLength', {
    get() {
      invoked++;
      throw new Error('Unexpected getter');
    },
  });
  try {
    const mac = await crypto.hmac(input, 'hmac');
    assert.deepEqual(
      mac,
      createHmac('sha256', f.values.get('hmac')!.bytes).update(Buffer.from('real input')).digest(),
    );
    assert.equal(invoked, 0);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 hung providers retain bounded slots after timeout and cannot acknowledge late work', async () => {
  const f = fixture(),
    entered = gate(),
    release = gate();
  let hanging = false,
    signal: AbortSignal | undefined;
  const secrets: SecretProvider = {
    async get(reference, options) {
      if (hanging) {
        signal = options?.signal;
        entered.release();
        await release.promise;
      }
      return f.values.get(reference)!;
    },
  };
  const { app, crypto } = await start({
    ...f.settings,
    secrets,
    policy: { maxConcurrent: 1, timeoutMs: 1000 },
  });
  try {
    hanging = true;
    const pending = crypto.hmac(Buffer.from('bounded'), 'hmac', { timeoutMs: 10 });
    await entered.promise;
    await assert.rejects(pending, code('EK_TIMEOUT'));
    assert.equal(signal?.aborted, true);
    await assert.rejects(crypto.hmac(Buffer.alloc(1), 'hmac'), code('EK_BACKEND_UNAVAILABLE'));
    release.release();
    await new Promise<void>((resolve) => setImmediate(resolve));
    hanging = false;
    assert.equal((await crypto.hmac(Buffer.alloc(1), 'hmac')).length, 32);
  } finally {
    release.release();
    await app.stop();
  }
});
test('EK-STD-SEC-009 snapshots mutable plaintext and AAD before provider awaits and preserves provider-owned keys', async () => {
  const f = fixture(),
    entered = gate(),
    release = gate();
  let hanging = false;
  const secrets: SecretProvider = {
    async get(reference) {
      if (hanging) {
        entered.release();
        await release.promise;
      }
      return f.values.get(reference)!;
    },
  };
  const { app, crypto } = await start({ ...f.settings, secrets });
  try {
    const input = Buffer.from('original'),
      aad = Buffer.from('purpose'),
      originalKey = Buffer.from(f.values.get('encryption')!.bytes);
    hanging = true;
    const result = crypto.encrypt(input, 'encryption', aad);
    await entered.promise;
    input.fill(0);
    aad.fill(0);
    release.release();
    const envelope = await result;
    hanging = false;
    assert.equal(
      Buffer.from(await crypto.decrypt(envelope, 'encryption', Buffer.from('purpose'))).toString(),
      'original',
    );
    assert.deepEqual(f.values.get('encryption')!.bytes, originalKey);
  } finally {
    release.release();
    await app.stop();
  }
});
test('EK-STD-SEC-009 shutdown aborts admitted work, rejects retained handles and isolates reused factories', async () => {
  const f = fixture(),
    entered = gate(),
    release = gate();
  let hanging = false;
  const secrets: SecretProvider = {
    async get(reference, options) {
      if (hanging) {
        entered.release();
        await release.promise;
        assert.equal(options?.signal?.aborted, true);
      }
      return f.values.get(reference)!;
    },
  };
  const plugin = cryptoPlugin({ ...f.settings, secrets }),
    apps: Application[] = [];
  try {
    for (let n = 0; n < 2; n++) {
      const app = await createApplication({ service, plugins: [plugin] });
      await app.start();
      apps.push(app);
    }
    const first = apps[0]!.resolve<CryptoService>(CRYPTO_CAPABILITY),
      second = apps[1]!.resolve<CryptoService>(CRYPTO_CAPABILITY);
    assert.notEqual(first, second);
    hanging = true;
    const pending = first.hmac(Buffer.alloc(1), 'hmac');
    const rejected = assert.rejects(
      pending,
      (error) => code('EK_ABORTED')(error) || code('EK_RESOURCE_CLOSED')(error),
    );
    await entered.promise;
    await apps[0]!.stop();
    await rejected;
    await assert.rejects(first.hmac(Buffer.alloc(1), 'hmac'), code('EK_RESOURCE_CLOSED'));
    release.release();
    hanging = false;
    assert.equal((await second.hmac(Buffer.alloc(1), 'hmac')).length, 32);
  } finally {
    release.release();
    await Promise.all(apps.map((app) => app.stop()));
  }
});
test('EK-STD-SEC-009 absent bootstrap keys prevent readiness and duplicate plugins cannot overwrite bindings', async () => {
  const f = fixture();
  f.values.delete('hmac');
  const app = await createApplication({ service, plugins: [cryptoPlugin(f.settings)] });
  await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
  assert.equal(app.state, 'CLOSED');
  await app.stop();
  await assert.rejects(
    createApplication({ service, plugins: [cryptoPlugin(f.settings), cryptoPlugin(f.settings)] }),
    code('EK_PLUGIN_DUPLICATE'),
  );
});

test('EK-STD-SEC-009 byte and metadata mutations never authenticate under a different AAD', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings);
  try {
    await fc.assert(
      fc.asyncProperty(
        fc.uint8Array({ maxLength: 256 }),
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        async (input, aad) => {
          const envelope = await crypto.encrypt(input, 'encryption', aad);
          assert.deepEqual(await crypto.decrypt(envelope, 'encryption', aad), Buffer.from(input));
          const changed = Buffer.from(aad);
          changed[0] = changed[0]! ^ 1;
          await assert.rejects(
            crypto.decrypt(envelope, 'encryption', changed),
            code('EK_CRYPTO_AUTH_FAILED'),
          );
        },
      ),
      { seed: 62381, numRuns: 100 },
    );
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 test-only providers cannot enter production or development and labels confer no trust', async () => {
  const f = fixture(),
    secrets = { ...f.secrets, usage: 'test-only' };
  for (const environment of ['production', 'development'] as const) {
    const app = await createApplication({
      service: { ...service, environment },
      plugins: [cryptoPlugin({ ...f.settings, secrets })],
    });
    await assert.rejects(app.start(), code('EK_PLUGIN_FAILED'));
    assert.equal(app.state, 'CLOSED');
    await app.stop();
  }
  assert.equal(f.calls(), 0);
  const { app, crypto } = await start({ ...f.settings, secrets });
  try {
    assert.equal((await crypto.hmac(Buffer.alloc(1), 'hmac')).length, 32);
  } finally {
    await app.stop();
  }
  const invalidUsage = { ...f.secrets, usage: 'unreviewed' };
  assert.throws(
    () => cryptoPlugin({ ...f.settings, secrets: invalidUsage }),
    code('EK_CONFIG_INVALID'),
  );
});
test('EK-STD-SEC-009 secret, operation and signal accessors are rejected without invocation', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings);
  let invoked = 0;
  const accessor = () => {
    invoked++;
    throw new Error('Untrusted accessor');
  };
  try {
    const options = Object.defineProperty({}, 'timeoutMs', { get: accessor, enumerable: true });
    await assert.rejects(crypto.hmac(Buffer.alloc(1), 'hmac', options), code('EK_CONFIG_INVALID'));
    const controller = new AbortController();
    Object.defineProperty(controller.signal, 'aborted', { get: accessor });
    await assert.rejects(
      crypto.hmac(Buffer.alloc(1), 'hmac', { signal: controller.signal }),
      code('EK_CONFIG_INVALID'),
    );
    const secret = Object.defineProperty({ keyVersion: 'getter' }, 'bytes', {
      get: accessor,
      enumerable: true,
    });
    f.values.set('encryption', secret as SecretValue);
    await assert.rejects(
      crypto.encrypt(Buffer.alloc(1), 'encryption'),
      code('EK_CRYPTO_KEY_UNAVAILABLE'),
    );
    const envelope = Object.defineProperty({}, 'nonce', { get: accessor, enumerable: true });
    await assert.rejects(crypto.decrypt(envelope as never, 'encryption'), code('EK_CRYPTO_FORMAT'));
    assert.equal(invoked, 0);
  } finally {
    await app.stop();
  }
});
test('EK-STD-SEC-009 caller cancellation reaches providers and small output budgets prevent secret retrieval', async () => {
  const f = fixture(),
    entered = gate(),
    release = gate();
  let hanging = false;
  const secrets: SecretProvider = {
    async get(reference, options) {
      if (hanging) {
        entered.release();
        await release.promise;
        assert.equal(options?.signal?.aborted, true);
      }
      return f.values.get(reference)!;
    },
  };
  const { app, crypto } = await start({ ...f.settings, secrets });
  try {
    hanging = true;
    const controller = new AbortController();
    const pending = crypto.hmac(Buffer.alloc(1), 'hmac', { signal: controller.signal });
    const rejected = assert.rejects(pending, code('EK_ABORTED'));
    await entered.promise;
    controller.abort();
    await rejected;
    release.release();
  } finally {
    release.release();
    await app.stop();
  }
  const small = await start({
    ...f.settings,
    policy: { maxConcurrent: 1, timeoutMs: 1000, maxOutputBytes: 16 },
  });
  try {
    const calls = f.calls();
    await assert.rejects(small.crypto.hmac(Buffer.alloc(1), 'hmac'), code('EK_CRYPTO_FORMAT'));
    await assert.rejects(small.crypto.sign(Buffer.alloc(1), 'ed'), code('EK_CRYPTO_FORMAT'));
    assert.equal(f.calls(), calls);
  } finally {
    await small.app.stop();
  }
});

test('EK-STD-SEC-009 unpreemptible work cannot return expired plaintext and unexpected failures remain sanitized', async () => {
  const f = fixture(),
    runtime = createRuntime(captureSettings(f.settings));
  const plaintext = Buffer.from('expired internal result');
  try {
    await assert.rejects(
      runtime.run({ timeoutMs: 5 }, async () => {
        // Model bounded native work that blocks the event loop beyond its deadline.
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
        return plaintext;
      }),
      code('EK_TIMEOUT'),
    );
    assert.ok(plaintext.every((value) => value === 0));
    await assert.rejects(
      runtime.run(undefined, async () => {
        throw new Error('private native diagnostic');
      }),
      (error) => {
        assert.ok(code('EK_CRYPTO_FORMAT')(error));
        assert.ok(error instanceof KitError);
        assert.equal(error.cause, undefined);
        assert.equal(error.message.includes('private'), false);
        return true;
      },
    );
  } finally {
    runtime.close();
    runtime.close();
  }
});
test('EK-STD-SEC-009 future secret expiry is accepted while weak HMAC material is rejected', async () => {
  const f = fixture();
  f.values.set('hmac', {
    ...f.values.get('hmac')!,
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  });
  const { app, crypto } = await start(f.settings);
  try {
    assert.equal((await crypto.hmac(Buffer.alloc(0), 'hmac')).length, 32);
    f.values.set('hmac', { bytes: Buffer.alloc(1), keyVersion: 'weak' });
    await assert.rejects(crypto.hmac(Buffer.alloc(0), 'hmac'), code('EK_CRYPTO_KEY_UNAVAILABLE'));
  } finally {
    await app.stop();
  }
});

test('EK-STD-SEC-009 every public operation rejects invalid deadlines, cancellation and closed ownership', async () => {
  const f = fixture(),
    { app, crypto } = await start(f.settings),
    input = Buffer.from('all public operations'),
    aad = Buffer.from('approved-purpose');
  try {
    const envelope = await crypto.encrypt(input, 'encryption', aad),
      mac = await crypto.hmac(input, 'hmac'),
      signature = await crypto.sign(input, 'ed');
    const publicKey = f.ed.publicKey.export({ format: 'der', type: 'spki' });
    const operations: readonly [string, (options?: OperationOptions) => Promise<unknown>][] = [
      ['encrypt', (options) => crypto.encrypt(input, 'encryption', aad, options)],
      ['decrypt', (options) => crypto.decrypt(envelope, 'encryption', aad, options)],
      ['hmac', (options) => crypto.hmac(input, 'hmac', options)],
      ['verifyMac', (options) => crypto.verifyMac(input, mac, 'hmac', options)],
      ['sign', (options) => crypto.sign(input, 'ed', options)],
      [
        'verifySignature',
        (options) => crypto.verifySignature(input, signature, publicKey, options),
      ],
    ];
    const controller = new AbortController();
    controller.abort();
    const before = f.calls();
    for (const [, operation] of operations) {
      await assert.rejects(operation({ timeoutMs: 0 }), code('EK_CONFIG_INVALID'));
      await assert.rejects(operation({ signal: controller.signal }), code('EK_ABORTED'));
    }
    assert.equal(f.calls(), before);
    f.values.clear();
    for (const [name, operation] of operations) {
      if (name === 'verifySignature') assert.equal(await operation(), true);
      else await assert.rejects(operation(), code('EK_CRYPTO_KEY_UNAVAILABLE'));
    }
    await app.stop();
    for (const [, operation] of operations)
      await assert.rejects(operation(), code('EK_RESOURCE_CLOSED'));
  } finally {
    await app.stop();
  }
});
