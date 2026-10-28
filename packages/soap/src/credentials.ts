// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types, toUSVString } from 'node:util';
import { X509Certificate } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import type { OperationOptions } from '@arkenivajs/core';
import type { Settings } from './settings.js';
import type { SoapServiceProfile } from './contracts.js';
import type { TlsMaterial } from './https.js';
import { fields, text } from './settings.js';
import { failure } from './validation.js';

const typedArray = Object.getPrototypeOf(Uint8Array.prototype),
  bufferGetter = Object.getOwnPropertyDescriptor(typedArray, 'buffer')!.get!,
  offsetGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteOffset')!.get!,
  lengthGetter = Object.getOwnPropertyDescriptor(typedArray, 'byteLength')!.get!;
function bytes(value: unknown): Buffer {
  if (!types.isUint8Array(value)) throw failure();
  const buffer = bufferGetter.call(value) as ArrayBuffer,
    offset = offsetGetter.call(value) as number,
    length = lengthGetter.call(value) as number;
  if (types.isSharedArrayBuffer(buffer) || length < 1 || length > 1048576) throw failure();
  return Buffer.from(new Uint8Array(buffer, offset, length));
}
function secretText(value: unknown, maximum = 65536): string {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > maximum ||
    Buffer.byteLength(value) > maximum ||
    toUSVString(value) !== value
  )
    throw failure();
  return value;
}
export interface Credentials {
  readonly version?: string;
  readonly material: TlsMaterial;
  readonly wsSecurity?: Readonly<{ username: string; password: string }>;
  clear(): void;
}
async function load(settings: Settings, reference: string, options: OperationOptions) {
  let owned: Buffer | undefined;
  try {
    const result = fields(await settings.get(reference, options), [
      'bytes',
      'keyVersion',
      'expiresAt',
    ]);
    const version = text(result.keyVersion, 128);
    if (result.expiresAt !== undefined) {
      const expires = Date.parse(text(result.expiresAt, 64));
      if (!Number.isFinite(expires) || expires <= Date.now()) throw failure();
    }
    owned = bytes(result.bytes);
    return { bytes: owned, version };
  } catch {
    owned?.fill(0);
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
}
/** Resolve versioned provider bytes; only supported explicit authentication modes reach the native client. */
export async function credentials(
  settings: Settings,
  profile: SoapServiceProfile,
  options: OperationOptions,
): Promise<Credentials> {
  const owned: Buffer[] = [];
  try {
    const material: {
      ca?: Buffer;
      cert?: Buffer;
      key?: Buffer;
      passphrase?: string;
      authorization?: string;
    } = {};
    let version: string | undefined,
      wsSecurity: Readonly<{ username: string; password: string }> | undefined;
    if (profile.trustedCaRef) {
      const value = await load(settings, profile.trustedCaRef, options);
      owned.push(value.bytes);
      if (!value.bytes.toString('utf8').includes('-----BEGIN CERTIFICATE-----')) throw failure();
      material.ca = value.bytes;
      const source = value.bytes.toString('utf8'),
        certificates = source.match(
          /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
        );
      if (
        !certificates?.length ||
        certificates.length > 32 ||
        source.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim()
      )
        throw failure();
      for (const certificate of certificates) new X509Certificate(certificate);
    }
    if (profile.credentialsRef) {
      const value = await load(settings, profile.credentialsRef, options);
      owned.push(value.bytes);
      const source = value.bytes.toString('utf8');
      if (!Buffer.from(source).equals(value.bytes)) throw failure();
      const bundle = fields(JSON.parse(source) as unknown, [
        'version',
        'httpAuth',
        'tls',
        'wsSecurity',
      ]);
      if (bundle.version !== 1 || (!bundle.httpAuth && !bundle.tls && !bundle.wsSecurity))
        throw failure();
      version = value.version;
      if (bundle.httpAuth !== undefined) {
        const auth = fields(bundle.httpAuth, ['scheme', 'username', 'password', 'token']);
        if (auth.scheme === 'basic') {
          const username = text(auth.username, 256),
            password = secretText(auth.password, 8192);
          if (username.includes(':') || auth.token !== undefined) throw failure();
          const framed = Buffer.from(username + ':' + password);
          try {
            material.authorization = 'Basic ' + framed.toString('base64');
          } finally {
            framed.fill(0);
          }
        } else if (auth.scheme === 'bearer') {
          if (auth.username !== undefined || auth.password !== undefined) throw failure();
          material.authorization = 'Bearer ' + secretText(auth.token, 8192);
          if (!/^Bearer [A-Za-z0-9+/=._~-]+$/.test(material.authorization)) throw failure();
        } else throw failure();
      }
      if (bundle.tls !== undefined) {
        const tls = fields(bundle.tls, ['certificatePem', 'privateKeyPem', 'passphrase']);
        material.cert = Buffer.from(secretText(tls.certificatePem));
        owned.push(material.cert);
        material.key = Buffer.from(secretText(tls.privateKeyPem));
        owned.push(material.key);
        if (tls.passphrase !== undefined) material.passphrase = secretText(tls.passphrase, 4096);
      }
      if (bundle.wsSecurity !== undefined) {
        const token = fields(bundle.wsSecurity, ['mode', 'username', 'password']);
        if (token.mode !== 'username-token-digest') throw failure();
        wsSecurity = Object.freeze({
          username: text(token.username, 256),
          password: secretText(token.password, 8192),
        });
      }
    }
    if (material.authorization && material.authorization.length > 8192) throw failure();
    if (material.ca || material.cert)
      createSecureContext({
        ...(material.ca ? { ca: material.ca } : {}),
        ...(material.cert ? { cert: material.cert, key: material.key } : {}),
        ...(material.passphrase ? { passphrase: material.passphrase } : {}),
        minVersion: 'TLSv1.2',
      });
    return Object.freeze({
      material: Object.freeze(material),
      ...(version === undefined ? {} : { version }),
      ...(wsSecurity ? { wsSecurity } : {}),
      clear() {
        for (const bytes of owned) bytes.fill(0);
      },
    });
  } catch {
    for (const bytes of owned) bytes.fill(0);
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
}
