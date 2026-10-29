// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createSamlService } from '../../dist/index.js';
import { fixture } from '../fixture.js';

test('Actual EC and weak RSA private keys cannot become SAML metadata signing credentials', async () => {
  const f = await fixture();
  try {
    for (const pair of [
      generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      generateKeyPairSync('rsa', { modulusLength: 1024 }),
    ]) {
      const bytes = Buffer.from(pair.privateKey.export({ format: 'pem', type: 'pkcs8' })),
        before = Buffer.from(bytes),
        service = createSamlService({
          ...f.settings,
          secretProvider: {
            async get(reference, options) {
              if (reference === f.settings.signingKeyRef) return { bytes, keyVersion: 'fixture' };
              return f.settings.secretProvider.get(reference, options);
            },
          },
        });
      await assert.rejects(service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
      assert.deepEqual(bytes, before);
    }
  } finally {
    await f.close();
  }
});

test('Fresh SP signing certificates are checked at both actual X509 validity boundaries', async () => {
  const f = await fixture(),
    certificate = new X509Certificate(await readFile(f.directory + '/sp.pem')),
    originalNow = Date.now;
  try {
    // Only this isolated test process clock changes; no operating-system or production clock changes.
    for (const instant of [
      Date.parse(certificate.validFrom) - 1,
      Date.parse(certificate.validTo),
    ]) {
      Date.now = () => instant;
      await assert.rejects(f.service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
    }
    Date.now = originalNow;
    assert.ok((await f.service.createMetadata()).includes('EntityDescriptor'));
  } finally {
    Date.now = originalNow;
    await f.close();
  }
});

test('Secret expiry, certificate-read failures and detached storage deny signing without altering provider bytes', async () => {
  const f = await fixture();
  try {
    const key = await f.settings.secretProvider.get(f.settings.signingKeyRef!),
      before = Buffer.from(key.bytes);
    for (const expiresAt of ['invalid', 1, new Date(Date.now() - 1).toISOString()]) {
      const service = createSamlService({
        ...f.settings,
        secretProvider: {
          async get() {
            return { ...key, expiresAt } as never;
          },
        },
      });
      await assert.rejects(service.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
      assert.deepEqual(key.bytes, before);
    }
    const failed = createSamlService({
      ...f.settings,
      secretProvider: {
        async get(reference) {
          if (reference === f.settings.signingKeyRef) return key;
          throw new Error('The disposable certificate provider is unavailable');
        },
      },
    });
    await assert.rejects(failed.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
    assert.deepEqual(key.bytes, before);
    const storage = new ArrayBuffer(8),
      bytes = new Uint8Array(storage);
    structuredClone(storage, { transfer: [storage] });
    const detached = createSamlService({
      ...f.settings,
      secretProvider: {
        async get() {
          return { bytes, keyVersion: 'fixture' };
        },
      },
    });
    await assert.rejects(detached.createMetadata(), { code: 'EK_SAML_CONFIGURATION' });
  } finally {
    await f.close();
  }
});

test('Native secret copying ignores executable Uint8Array metadata and retains real signing credentials', async () => {
  const f = await fixture();
  let effects = 0;
  const originals: { bytes: Uint8Array; before: Buffer }[] = [];
  try {
    const service = createSamlService({
      ...f.settings,
      secretProvider: {
        async get(reference, options) {
          const value = await f.settings.secretProvider.get(reference, options),
            bytes = Uint8Array.from(value.bytes);
          originals.push({ bytes, before: Buffer.from(bytes) });
          for (const name of ['buffer', 'byteLength', 'byteOffset', 'slice', 'fill']) {
            Object.defineProperty(bytes, name, {
              get() {
                effects++;
                throw new Error('Executable secret storage metadata');
              },
            });
          }
          return { ...value, bytes };
        },
      },
    });
    const metadata = await service.createMetadata(),
      certificate = new X509Certificate(await readFile(f.directory + '/sp.pem'));
    assert.ok(metadata.replace(/\s/gu, '').includes(certificate.raw.toString('base64')));
    assert.equal(effects, 0);
    assert.equal(originals.length, 2);
    for (const value of originals) assert.deepEqual([...value.bytes], [...value.before]);
  } finally {
    await f.close();
  }
});
