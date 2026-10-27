// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { CryptoService, SealedEnvelope } from '@arkenivajs/security-crypto';
import { freezeData } from '@arkenivajs/core/support';
import type { IdentitySubject } from './contracts.js';
import type { Settings, Call } from './runtime.js';
import { data, failure, id, instant, snapshot, strings, subject, text } from './validation.js';

export type StateKind = 'authorization' | 'refresh' | 'family';
export const namespaces = Object.freeze({
  authorization: 'oauth.authorization.v1',
  refresh: 'oauth.refresh.v1',
  family: 'oauth.families.v1',
});
interface EncodedEnvelope {
  readonly version: 1;
  readonly algorithm: 'AES-256-GCM';
  readonly keyId: string;
  readonly nonce: string;
  readonly ciphertext: string;
  readonly tag: string;
}
export interface State {
  readonly kind: StateKind;
  readonly id: string;
  readonly status: 'active' | 'spent';
  readonly owner: IdentitySubject;
  readonly ownerKey: string;
  readonly clientId: string;
  readonly issuer: string;
  readonly audience: string;
  readonly scopes: readonly string[];
  readonly expiresAt: string;
  readonly encRef: string;
  readonly macRef: string;
  readonly familyId?: string;
  readonly epoch?: number;
  readonly sealed: EncodedEnvelope;
  readonly digest: string;
  readonly version: string;
}
export type StateMetadata = Omit<State, 'ownerKey' | 'sealed' | 'digest' | 'version'>;
export type StateBody = Omit<State, 'version'>;
const length = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'byteLength',
  )!.get!,
  backing = Object.getOwnPropertyDescriptor(
    Object.getPrototypeOf(Uint8Array.prototype),
    'buffer',
  )!.get!;
function bytes(input: unknown, maximum: number, exact?: number): Buffer {
  if (!(input instanceof Uint8Array) || backing.call(input) instanceof SharedArrayBuffer)
    throw failure('EK_OAUTH_STATE');
  const size: number = length.call(input);
  if (size > maximum || (exact !== undefined && size !== exact)) throw failure('EK_OAUTH_STATE');
  const result = Buffer.alloc(size);
  Uint8Array.prototype.set.call(result, input);
  return result;
}
function base64(input: unknown, maximum: number, exact?: number): Buffer {
  if (
    typeof input !== 'string' ||
    input.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(input)
  )
    throw failure('EK_OAUTH_STATE');
  const result = Buffer.from(input, 'base64url');
  if (
    result.length > maximum ||
    (exact !== undefined && result.length !== exact) ||
    result.toString('base64url') !== input
  )
    throw failure('EK_OAUTH_STATE');
  return result;
}
function encoded(input: SealedEnvelope): EncodedEnvelope {
  const value = data(input, ['version', 'algorithm', 'keyId', 'nonce', 'ciphertext', 'tag']);
  if (value.version !== 1 || value.algorithm !== 'AES-256-GCM') throw failure('EK_OAUTH_STATE');
  text(value.keyId, 256);
  return Object.freeze({
    version: 1,
    algorithm: 'AES-256-GCM',
    keyId: value.keyId,
    nonce: bytes(value.nonce, 12, 12).toString('base64url'),
    ciphertext: bytes(value.ciphertext, 16384).toString('base64url'),
    tag: bytes(value.tag, 16, 16).toString('base64url'),
  });
}
function envelope(input: unknown): SealedEnvelope {
  const value = data(input, ['version', 'algorithm', 'keyId', 'nonce', 'ciphertext', 'tag']);
  if (value.version !== 1 || value.algorithm !== 'AES-256-GCM') throw failure('EK_OAUTH_STATE');
  text(value.keyId, 256);
  return Object.freeze({
    version: 1,
    algorithm: 'AES-256-GCM',
    keyId: value.keyId,
    nonce: base64(value.nonce, 12, 12),
    ciphertext: base64(value.ciphertext, 16384),
    tag: base64(value.tag, 16, 16),
  });
}
function minimal(owner: IdentitySubject): IdentitySubject {
  return freezeData({
    issuer: owner.issuer,
    subject: owner.subject,
    ...(owner.tenant
      ? {
          tenant: {
            ...owner.tenant,
            identity: {
              issuer: owner.issuer,
              subject: owner.subject,
              audience: [],
              scopes: [],
              claims: {},
            },
          },
        }
      : {}),
  });
}
function aad(row: StateMetadata & { readonly ownerKey: string }): Buffer {
  return Buffer.from(
    JSON.stringify([
      'arkenivajs.oauth.state.v1',
      row.kind,
      row.id,
      row.owner.issuer,
      row.owner.subject,
      row.owner.tenant?.tenantId ?? '',
      row.ownerKey,
      row.clientId,
      row.issuer,
      row.audience,
      row.scopes,
      row.expiresAt,
      row.encRef,
      row.macRef,
      row.familyId ?? '',
      row.epoch ?? 0,
    ]),
  );
}
const receipt = (input: unknown) => {
  const value = data(input, ['committed', 'version']);
  if (typeof value.committed !== 'boolean') throw failure('EK_OAUTH_STATE');
  if (value.version !== undefined) text(value.version, 256);
  return value.committed;
};
/** Encrypted payloads and keyed reference proofs are bound to the canonical account and exact flow. */
export function createStateCodec(settings: Settings, crypto: CryptoService) {
  const options = (call: Call) => ({ signal: call.options().signal! });
  async function mac(input: Buffer, reference: string, call: Call): Promise<string> {
    try {
      return bytes(
        await call.step('EK_OAUTH_STATE', () => crypto.hmac(input, reference, options(call))),
        32,
        32,
      ).toString('hex');
    } finally {
      input.fill(0);
    }
  }
  const ownerKey = (owner: IdentitySubject, reference: string, call: Call) =>
    mac(
      Buffer.from(
        JSON.stringify([
          'arkenivajs.oauth.owner.v1',
          owner.issuer,
          owner.subject,
          owner.tenant?.tenantId ?? '',
        ]),
      ),
      reference,
      call,
    );
  const proof = (row: StateMetadata & { readonly ownerKey: string }, secret: string) => {
    const context = aad(row);
    try {
      return Buffer.from(
        JSON.stringify([
          'arkenivajs.oauth.reference.v1',
          context.toString('base64url'),
          row.status,
          secret,
        ]),
      );
    } finally {
      context.fill(0);
    }
  };
  function parse(input: unknown, kind: StateKind, key: string): State {
    try {
      const value = data(input, [
        'kind',
        'id',
        'status',
        'owner',
        'ownerKey',
        'clientId',
        'issuer',
        'audience',
        'scopes',
        'expiresAt',
        'encRef',
        'macRef',
        'familyId',
        'epoch',
        'sealed',
        'digest',
        'version',
      ]);
      if (
        value.kind !== kind ||
        value.id !== key ||
        !['active', 'spent'].includes(value.status as string)
      )
        throw failure('EK_OAUTH_STATE');
      id(value.id);
      text(value.ownerKey, 64);
      text(value.clientId, 128);
      text(value.issuer, 2048);
      text(value.audience, 512);
      text(value.version, 256);
      if (
        typeof value.digest !== 'string' ||
        !/^[a-f0-9]{64}$/.test(value.digest) ||
        !/^[a-f0-9]{64}$/.test(value.ownerKey)
      )
        throw failure('EK_OAUTH_STATE');
      if (
        typeof value.encRef !== 'string' ||
        !settings.encryptionRefs.includes(value.encRef) ||
        typeof value.macRef !== 'string' ||
        !settings.macRefs.includes(value.macRef)
      )
        throw failure('EK_OAUTH_STATE');
      if (kind === 'authorization') {
        if (value.familyId !== undefined || value.epoch !== undefined)
          throw failure('EK_OAUTH_STATE');
      } else {
        id(value.familyId);
        if (
          !Number.isSafeInteger(value.epoch) ||
          (value.epoch as number) < 0 ||
          (kind === 'family' && value.id !== value.familyId)
        )
          throw failure('EK_OAUTH_STATE');
      }
      const protectedEnvelope = envelope(value.sealed);
      return freezeData({
        kind,
        id: value.id,
        status: value.status as 'active' | 'spent',
        owner: subject(value.owner),
        ownerKey: value.ownerKey,
        clientId: value.clientId,
        issuer: value.issuer,
        audience: value.audience,
        scopes: strings(value.scopes, 64),
        expiresAt: instant(value.expiresAt),
        encRef: value.encRef,
        macRef: value.macRef,
        ...(kind === 'authorization'
          ? {}
          : { familyId: value.familyId as string, epoch: value.epoch as number }),
        sealed: encoded(protectedEnvelope),
        digest: value.digest,
        version: value.version,
      });
    } catch {
      throw failure('EK_OAUTH_STATE');
    }
  }
  const body = (row: State): StateBody => {
    const { version, ...value } = row;
    void version;
    return Object.freeze(value);
  };
  return {
    receipt,
    body,
    async read(kind: StateKind, key: string, call: Call) {
      id(key);
      const value = await call.step('EK_OAUTH_STATE', (opts) =>
        settings.store.read(namespaces[kind], key, opts),
      );
      return value === null ? null : parse(value, kind, key);
    },
    async make(
      meta: StateMetadata,
      payload: Readonly<Record<string, unknown>>,
      secret: string,
      call: Call,
    ): Promise<StateBody> {
      const owner = minimal(meta.owner),
        index = await ownerKey(owner, meta.macRef, call),
        value = { ...meta, owner, ownerKey: index },
        context = aad(value),
        plain = Buffer.from(JSON.stringify(snapshot(payload)));
      try {
        const sealed = encoded(
            await call.step('EK_OAUTH_STATE', () =>
              crypto.encrypt(plain, meta.encRef, context, options(call)),
            ),
          ),
          digest = await mac(proof(value, secret), meta.macRef, call),
          result = freezeData({ ...value, sealed, digest });
        if (Buffer.byteLength(JSON.stringify(result)) > 32768) throw failure('EK_OAUTH_STATE');
        return result;
      } finally {
        plain.fill(0);
        context.fill(0);
      }
    },
    async prove(row: State, secret: string, call: Call) {
      const input = proof(row, secret),
        expected = Buffer.from(row.digest, 'hex');
      try {
        const valid = await call.step('EK_OAUTH_STATE', () =>
          crypto.verifyMac(input, expected, row.macRef, options(call)),
        );
        if (typeof valid !== 'boolean') throw failure('EK_OAUTH_STATE');
        return valid && row.ownerKey === (await ownerKey(row.owner, row.macRef, call));
      } finally {
        input.fill(0);
        expected.fill(0);
      }
    },
    async open(row: State, call: Call): Promise<Readonly<Record<string, unknown>>> {
      const context = aad(row);
      let plain: Buffer | undefined;
      try {
        plain = bytes(
          await call.step('EK_OAUTH_STATE', () =>
            crypto.decrypt(envelope(row.sealed), row.encRef, context, options(call)),
          ),
          16384,
        );
        const parsed = snapshot(JSON.parse(plain.toString('utf8')) as unknown);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
          throw failure('EK_OAUTH_STATE');
        return parsed as Readonly<Record<string, unknown>>;
      } catch {
        call.check();
        throw failure('EK_OAUTH_STATE');
      } finally {
        plain?.fill(0);
        context.fill(0);
      }
    },
    async spend(row: State, secret: string, call: Call) {
      const next = { ...body(row), status: 'spent' as const };
      return freezeData({ ...next, digest: await mac(proof(next, secret), row.macRef, call) });
    },
    async familyKey(row: Pick<State, 'owner' | 'macRef' | 'familyId'>, call: Call) {
      if (!row.familyId) throw failure('EK_OAUTH_STATE');
      return mac(
        Buffer.from(
          JSON.stringify([
            'arkenivajs.oauth.family.v1',
            row.owner.issuer,
            row.owner.subject,
            row.owner.tenant?.tenantId ?? '',
            row.familyId,
          ]),
        ),
        row.macRef,
        call,
      );
    },
  };
}
