// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash, randomBytes } from 'node:crypto';
import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { freezeData, within } from '@arkenivajs/core/support';
import type { CryptoService, SealedEnvelope } from '@arkenivajs/security-crypto';
import type { FederationAssurance, FederationProfileV1 } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import { failure, fields, method, text, url } from './validation.js';

const length = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'byteLength',
  )!.get!,
  backing = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'buffer',
  )!.get!;
function bytes(value: unknown, maximum: number, exact?: number): Buffer {
  if (!types.isUint8Array(value) || backing.call(value) instanceof SharedArrayBuffer)
    throw failure('EK_EID_FEDERATION');
  const size: number = length.call(value);
  if (size > maximum || (exact !== undefined && size !== exact)) throw failure('EK_EID_FEDERATION');
  const copy = Buffer.alloc(size);
  Uint8Array.prototype.set.call(copy, value);
  return copy;
}
function base64(value: unknown, maximum: number, exact?: number) {
  if (
    typeof value !== 'string' ||
    value.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  )
    throw failure('EK_EID_FEDERATION');
  const decoded = Buffer.from(value, 'base64url');
  if (
    decoded.length > maximum ||
    decoded.toString('base64url') !== value ||
    (exact !== undefined && decoded.length !== exact)
  )
    throw failure('EK_EID_FEDERATION');
  return decoded;
}
function loginReference(value: unknown): string {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/u.test(value))
    throw failure('EK_EID_FEDERATION');
  return value;
}
function envelope(value: unknown): SealedEnvelope {
  const data = fields(value, ['version', 'algorithm', 'keyId', 'nonce', 'ciphertext', 'tag']);
  if (data.version !== 1 || data.algorithm !== 'AES-256-GCM') throw failure('EK_EID_FEDERATION');
  return Object.freeze({
    version: 1,
    algorithm: 'AES-256-GCM',
    keyId: text(data.keyId),
    nonce: base64(data.nonce, 12, 12),
    ciphertext: base64(data.ciphertext, 16384),
    tag: base64(data.tag, 16, 16),
  });
}
function encode(input: SealedEnvelope) {
  const value = fields(input, ['version', 'algorithm', 'keyId', 'nonce', 'ciphertext', 'tag']);
  if (value.version !== 1 || value.algorithm !== 'AES-256-GCM') throw failure('EK_EID_FEDERATION');
  return Object.freeze({
    version: 1,
    algorithm: 'AES-256-GCM',
    keyId: text(value.keyId),
    nonce: bytes(value.nonce, 12, 12).toString('base64url'),
    ciphertext: bytes(value.ciphertext, 16384).toString('base64url'),
    tag: bytes(value.tag, 16, 16).toString('base64url'),
  });
}
export function returnPath(input: unknown) {
  if (
    typeof input !== 'string' ||
    !input.startsWith('/') ||
    input.startsWith('//') ||
    input.includes('\\') ||
    Buffer.byteLength(input) > 2048 ||
    [...input].some((character) => character.charCodeAt(0) <= 32 || character.charCodeAt(0) === 127)
  )
    throw failure('EK_EID_PROFILE');
  const parsed = new URL(input, 'https://return.invalid');
  if (parsed.origin !== 'https://return.invalid' || parsed.hash) throw failure('EK_EID_PROFILE');
  return input;
}
export interface LoginTransaction {
  readonly transactionId: string;
  readonly issuer: string;
  readonly assurance: FederationAssurance;
  readonly nonce: string;
  readonly verifier: string;
  readonly returnPath: string;
  readonly tenantHint?: string;
  readonly expiresAt: string;
}
/** Pre-session hints stay encrypted data; they confer neither account nor tenant authorization. */
export class FederationTransactions {
  private readonly profile: FederationProfileV1;
  private readonly namespace: string;
  private readonly fingerprint: string;
  private readonly crypto: Pick<CryptoService, 'encrypt' | 'decrypt' | 'hmac'>;
  constructor(
    private readonly settings: Settings,
    profileId: string,
    crypto: CryptoService,
  ) {
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId);
    if (!profile || !settings.encryptionRefs.length || !settings.macRefs.length) throw failure();
    this.profile = profile;
    this.namespace = 'arkenivajs.' + profile.system + '.authorization.v1';
    this.fingerprint = createHash('sha256').update(JSON.stringify(profile)).digest('hex');
    this.crypto = Object.freeze({
      encrypt: method<CryptoService['encrypt']>(crypto, 'encrypt'),
      decrypt: method<CryptoService['decrypt']>(crypto, 'decrypt'),
      hmac: method<CryptoService['hmac']>(crypto, 'hmac'),
    });
  }
  private async storage<T>(
    call: FederationCall,
    work: (options: { signal: AbortSignal; timeoutMs: number }) => Promise<T>,
  ) {
    return call.step((options) => {
      const limited = {
          signal: options.signal,
          timeoutMs: Math.min(options.timeoutMs, this.settings.stateStore.operationTimeoutMs),
        },
        actual = Promise.resolve().then(() => work(limited));
      call.track(actual);
      return within(() => actual, limited);
    });
  }
  private async lookup(
    call: FederationCall,
    token: string,
    reference: string,
    domain = 'arkenivajs.federation.transaction.id.v1',
  ) {
    const input = Buffer.from(JSON.stringify([domain, this.fingerprint, token]));
    try {
      return bytes(
        await call.step((options) => this.crypto.hmac(input, reference, options)),
        32,
        32,
      ).toString('hex');
    } finally {
      input.fill(0);
    }
  }
  private context(
    id: string,
    issuer: string,
    assurance: FederationAssurance,
    expiresAt: string,
    encryption: string,
    mac: string,
  ) {
    return Buffer.from(
      JSON.stringify([
        'arkenivajs.federation.transaction.body.v1',
        this.fingerprint,
        id,
        issuer,
        assurance,
        expiresAt,
        encryption,
        mac,
      ]),
    );
  }
  /** Probe only an unpredictable absent record without creating state or claiming a ceremony. */
  async probe(call: FederationCall): Promise<void> {
    const value = await this.storage(call, (options) =>
      this.settings.stateStore.store.read(this.namespace, randomBytes(32).toString('hex'), options),
    );
    if (value !== null) throw failure('EK_EID_FEDERATION');
  }
  async create(
    call: FederationCall,
    input: {
      issuer: string;
      assurance: FederationAssurance;
      returnPath: string;
      tenantHint?: string;
    },
  ): Promise<LoginTransaction> {
    try {
      call.check();
      const value = fields(input, ['issuer', 'assurance', 'returnPath', 'tenantHint']),
        issuer = url(value.issuer),
        assurance = value.assurance as FederationAssurance,
        path = returnPath(value.returnPath),
        tenantHint = value.tenantHint === undefined ? undefined : text(value.tenantHint);
      if (
        !this.profile.expectedIssuers.includes(issuer) ||
        !this.profile.allowedAssurance.includes(assurance)
      )
        throw failure('EK_EID_PROFILE');
      const transactionId = randomBytes(32).toString('hex'),
        nonce = randomBytes(32).toString('hex'),
        verifier = randomBytes(32).toString('base64url'),
        expires = Date.now() + this.profile.sessionTtlSeconds * 1000;
      if (!Number.isSafeInteger(expires)) throw failure();
      const expiresAt = new Date(expires).toISOString(),
        encRef = this.settings.encryptionRefs[0]!,
        macRef = this.settings.macRefs[0]!,
        id = await this.lookup(call, transactionId, macRef),
        ownerKey = await this.lookup(
          call,
          this.profile.entityId,
          macRef,
          'arkenivajs.federation.registration.owner.v1',
        ),
        aad = this.context(id, issuer, assurance, expiresAt, encRef, macRef),
        plain = Buffer.from(
          JSON.stringify({
            nonce,
            verifier,
            returnPath: path,
            ...(tenantHint === undefined ? {} : { tenantHint }),
          }),
        );
      try {
        const sealed = encode(
            await call.step((options) => this.crypto.encrypt(plain, encRef, aad, options)),
          ),
          row = freezeData({
            id,
            ownerKey,
            fingerprint: this.fingerprint,
            issuer,
            assurance,
            expiresAt,
            encRef,
            macRef,
            sealed,
          });
        if (
          Buffer.byteLength(JSON.stringify(row)) >
          Math.min(32768, this.settings.policy.maxInputBytes ?? 32768)
        )
          throw failure('EK_EID_FEDERATION');
        const receipt = fields(
          await this.storage(call, (options) =>
            this.settings.stateStore.store.compareAndSet(this.namespace, id, null, row, options),
          ),
          ['committed', 'version'],
        );
        if (receipt.committed !== true) throw failure('EK_EID_FEDERATION');
        text(receipt.version);
        call.check();
        return freezeData({
          transactionId,
          issuer,
          assurance,
          nonce,
          verifier,
          returnPath: path,
          ...(tenantHint === undefined ? {} : { tenantHint }),
          expiresAt,
        });
      } finally {
        plain.fill(0);
        aad.fill(0);
      }
    } catch (error) {
      if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code))
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
  async consume(
    call: FederationCall,
    token: string,
    expectedIssuer: string,
  ): Promise<LoginTransaction> {
    try {
      call.check();
      loginReference(token);
      const issuer = url(expectedIssuer);
      if (!this.profile.expectedIssuers.includes(issuer)) throw failure('EK_EID_FEDERATION');
      for (const macRef of this.settings.macRefs) {
        const id = await this.lookup(call, token, macRef),
          stored = await this.storage(call, (options) =>
            this.settings.stateStore.store.read(this.namespace, id, options),
          );
        if (stored === null) continue;
        const row = fields(stored, [
            'id',
            'ownerKey',
            'fingerprint',
            'issuer',
            'assurance',
            'expiresAt',
            'encRef',
            'macRef',
            'sealed',
            'version',
          ]),
          assurance = row.assurance as FederationAssurance,
          encRef = text(row.encRef),
          expiresAt = text(row.expiresAt, 32),
          expires = Date.parse(expiresAt);
        text(row.version);
        const ownerKey = await this.lookup(
          call,
          this.profile.entityId,
          macRef,
          'arkenivajs.federation.registration.owner.v1',
        );
        if (
          row.id !== id ||
          row.ownerKey !== ownerKey ||
          row.fingerprint !== this.fingerprint ||
          row.issuer !== issuer ||
          row.macRef !== macRef ||
          !this.settings.encryptionRefs.includes(encRef) ||
          !this.profile.allowedAssurance.includes(assurance) ||
          !Number.isSafeInteger(expires) ||
          expires <= Date.now() ||
          new Date(expires).toISOString() !== expiresAt
        )
          throw failure('EK_EID_FEDERATION');
        const aad = this.context(id, issuer, assurance, expiresAt, encRef, macRef);
        let plain: Buffer | undefined;
        try {
          await call.step(async (options) => {
            const decrypted = await this.crypto.decrypt(envelope(row.sealed), encRef, aad, options);
            try {
              call.check();
              plain = bytes(decrypted, 16384);
            } finally {
              if (
                types.isUint8Array(decrypted) &&
                !(backing.call(decrypted) instanceof SharedArrayBuffer)
              )
                Uint8Array.prototype.fill.call(decrypted, 0);
            }
          });
          if (!plain) throw failure('EK_EID_FEDERATION');
          const data = fields(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain)), [
            'nonce',
            'verifier',
            'returnPath',
            'tenantHint',
          ]);
          loginReference(data.nonce);
          base64(data.verifier, 32, 32);
          const path = returnPath(data.returnPath),
            tenantHint = data.tenantHint === undefined ? undefined : text(data.tenantHint),
            claim = createHash('sha256')
              .update(
                JSON.stringify([
                  'arkenivajs.federation.transaction.consume.v1',
                  this.fingerprint,
                  token,
                ]),
              )
              .digest('hex'),
            committed = await this.storage(call, (options) =>
              this.settings.stateStore.store.claimOnce(
                this.namespace + '.spent',
                claim,
                expiresAt,
                options,
              ),
            );
          if (committed !== true || Date.now() >= expires) throw failure('EK_EID_FEDERATION');
          call.check();
          return freezeData({
            transactionId: token,
            issuer,
            assurance,
            expiresAt,
            nonce: data.nonce as string,
            verifier: data.verifier as string,
            returnPath: path,
            ...(tenantHint === undefined ? {} : { tenantHint }),
          });
        } finally {
          plain?.fill(0);
          aad.fill(0);
        }
      }
      throw failure('EK_EID_FEDERATION');
    } catch (error) {
      if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code))
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
}
