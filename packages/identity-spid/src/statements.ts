// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createPublicKey } from 'node:crypto';
import type { KeyObject, JsonWebKey } from 'node:crypto';
import { decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { freezeData, within } from '@arkenivajs/core/support';
import type { OperationOptions } from '@arkenivajs/core';
import { KitError } from '@arkenivajs/core';
import type { FederationTrustAnchor } from './contracts.js';
import { failure, fields, integer, list, text, url } from './validation.js';

const algorithms = ['RS256', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'];
export interface StatementKey {
  readonly kid: string;
  readonly publicKey: KeyObject;
  readonly validFrom?: number;
  readonly expiresAt?: number;
  readonly algorithm?: string;
}
export interface SignedStatement {
  readonly issuer: string;
  readonly subject: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly keys: readonly StatementKey[];
  readonly claims: Readonly<Record<string, unknown>>;
}
/** Signature evidence alone grants neither federation participation nor application identity. */
export interface StatementVerification {
  readonly issuer: string;
  readonly subject: string;
  readonly keys: readonly StatementKey[];
  readonly maxBytes: number;
  readonly track?: (task: Promise<unknown>) => void;
}
interface TokenVerification extends Omit<StatementVerification, 'subject'> {
  readonly subject?: string;
  readonly type: 'entity-statement+jwt' | 'trust-mark+jwt' | 'trust-mark-status-response+jwt';
  readonly requiredClaims: readonly string[];
  readonly maxAgeSeconds?: number;
}
function key(input: KeyObject): KeyObject {
  if (!(
    (input.asymmetricKeyType === 'rsa' &&
      (input.asymmetricKeyDetails?.modulusLength ?? 0) >= 2048) ||
    (input.asymmetricKeyType === 'ec' &&
      ['prime256v1', 'secp384r1', 'secp521r1'].includes(
        input.asymmetricKeyDetails?.namedCurve ?? '',
      ))
  ))
    throw failure('EK_EID_FEDERATION');
  return input;
}
/** Only currently valid configured roots may bootstrap statement signature verification. */
export function anchorKeys(
  anchors: readonly FederationTrustAnchor[],
  issuer: string,
): readonly StatementKey[] {
  const now = Date.now();
  const result = anchors
    .filter(
      (anchor) =>
        anchor.issuer === issuer &&
        Date.parse(anchor.validFrom) <= now &&
        now < Date.parse(anchor.expiresAt),
    )
    .map((anchor) =>
      Object.freeze({
        kid: anchor.kid,
        publicKey: key(createPublicKey(anchor.publicKeyPem)),
        validFrom: Date.parse(anchor.validFrom),
        expiresAt: Date.parse(anchor.expiresAt),
      }),
    );
  if (!result.length) throw failure('EK_EID_FEDERATION');
  return Object.freeze(result);
}
function boundedClaims(input: unknown): Readonly<Record<string, unknown>> {
  let nodes = 0;
  const visit = (value: unknown, depth: number): unknown => {
    if (++nodes > 4096 || depth > 16) throw failure('EK_EID_FEDERATION');
    if (
      value === null ||
      typeof value === 'boolean' ||
      typeof value === 'string' ||
      (typeof value === 'number' && Number.isFinite(value))
    )
      return value;
    if (Array.isArray(value))
      return value.length === 0 ? [] : list(value, 256).map((item) => visit(item, depth + 1));
    const object = fields(value),
      result: Record<string, unknown> = Object.create(null);
    if (Object.keys(object).length > 256) throw failure('EK_EID_FEDERATION');
    for (const [name, item] of Object.entries(object)) result[name] = visit(item, depth + 1);
    return result;
  };
  return freezeData(fields(visit(input, 0)));
}
/** Unverified claims may guide bounded approved discovery, but never authorize identity or keys. */
export function inspectConfiguration(token: string, maxBytes: number) {
  try {
    integer(maxBytes);
    if (
      typeof token !== 'string' ||
      Buffer.byteLength(token) > maxBytes ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(token)
    )
      throw failure('EK_EID_FEDERATION');
    const header = fields(decodeProtectedHeader(token), ['typ', 'alg', 'kid']);
    if (header.typ !== 'entity-statement+jwt' || !algorithms.includes(header.alg as string))
      throw failure('EK_EID_FEDERATION');
    text(header.kid);
    const claims = boundedClaims(decodeJwt(token));
    const entity = url(claims.iss);
    if (claims.sub !== entity) throw failure('EK_EID_FEDERATION');
    return Object.freeze({ entity, claims });
  } catch {
    throw failure('EK_EID_FEDERATION');
  }
}
/** Parse only public federation JWKS; private/symmetric material never becomes a verification key. */
function publicKeys(input: unknown, expiresAt: number): readonly StatementKey[] {
  const jwks = fields(input, ['keys']);
  const result = list(jwks.keys, 32).map((item) => {
    const jwk = fields(item, [
      'kid',
      'kty',
      'n',
      'e',
      'x',
      'y',
      'crv',
      'alg',
      'use',
      'key_ops',
      'x5c',
      'x5t',
      'x5t#S256',
    ]);
    const kid = text(jwk.kid);
    if (
      !['RSA', 'EC'].includes(jwk.kty as string) ||
      (jwk.alg !== undefined && !algorithms.includes(jwk.alg as string)) ||
      (jwk.use !== undefined && jwk.use !== 'sig') ||
      (jwk.key_ops !== undefined && list(jwk.key_ops).some((operation) => operation !== 'verify'))
    )
      throw failure('EK_EID_FEDERATION');
    return Object.freeze({
      kid,
      publicKey: key(createPublicKey({ format: 'jwk', key: jwk as JsonWebKey })),
      expiresAt,
      ...(jwk.alg === undefined ? {} : { algorithm: jwk.alg as string }),
    });
  });
  if (new Set(result.map((item) => item.kid)).size !== result.length)
    throw failure('EK_EID_FEDERATION');
  return Object.freeze(result);
}
/** JOSE owns JWS/JWT verification; callers must separately verify chain, policy and live revocation. */
export async function verifyFederationToken(
  token: string,
  expected: TokenVerification,
  options?: OperationOptions,
) {
  try {
    integer(expected.maxBytes);
    url(expected.issuer);
    if (expected.subject !== undefined) url(expected.subject);
    if (
      typeof token !== 'string' ||
      Buffer.byteLength(token) > expected.maxBytes ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(token)
    )
      throw failure('EK_EID_FEDERATION');
    const header = fields(decodeProtectedHeader(token), ['typ', 'alg', 'kid']);
    if (header.typ !== expected.type || !algorithms.includes(header.alg as string))
      throw failure('EK_EID_FEDERATION');
    const kid = text(header.kid),
      keys = expected.keys.filter((item) => item.kid === kid);
    if (keys.length !== 1) throw failure('EK_EID_FEDERATION');
    if (keys[0]!.publicKey.type !== 'public') throw failure('EK_EID_FEDERATION');
    const signing = keys[0]!;
    if (signing.algorithm !== undefined && signing.algorithm !== header.alg)
      throw failure('EK_EID_FEDERATION');
    const active = () => {
      const now = Date.now();
      if (
        (signing.validFrom !== undefined &&
          (!Number.isSafeInteger(signing.validFrom) || now < signing.validFrom)) ||
        (signing.expiresAt !== undefined &&
          (!Number.isSafeInteger(signing.expiresAt) || now >= signing.expiresAt))
      )
        throw failure('EK_EID_FEDERATION');
    };
    active();
    const result = await within(() => {
      const actual = jwtVerify(token, keys[0]!.publicKey, {
        algorithms,
        typ: expected.type,
        issuer: expected.issuer,
        ...(expected.subject === undefined ? {} : { subject: expected.subject }),
        requiredClaims: [...new Set(['iss', 'iat', ...expected.requiredClaims])],
        ...(expected.maxAgeSeconds === undefined
          ? {}
          : { maxTokenAge: integer(expected.maxAgeSeconds) }),
        clockTolerance: 0,
      });
      void actual.catch(() => undefined);
      expected.track?.(actual);
      return actual;
    }, options);
    const claims = boundedClaims(result.payload),
      issuedAt = claims.iat,
      expiresAt = claims.exp,
      now = Date.now() / 1000;
    active();
    if (
      !Number.isSafeInteger(issuedAt) ||
      (issuedAt as number) < 0 ||
      (issuedAt as number) > now ||
      (expiresAt !== undefined &&
        (!Number.isSafeInteger(expiresAt) ||
          (expiresAt as number) <= now ||
          (expiresAt as number) <= (issuedAt as number)))
    )
      throw failure('EK_EID_FEDERATION');
    const effectiveExpiry = Math.min(
      expiresAt === undefined ? Infinity : (expiresAt as number),
      signing.expiresAt === undefined ? Infinity : signing.expiresAt / 1000,
    );
    return Object.freeze({
      expiresAt: effectiveExpiry,
      claims,
    });
  } catch (error) {
    if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) throw error;
    throw failure('EK_EID_FEDERATION');
  }
}

/** Entity statements require public descendant keys as well as explicit bounded expiry. */
export async function verifyStatement(
  token: string,
  expected: StatementVerification,
  options?: OperationOptions,
): Promise<SignedStatement> {
  try {
    const verified = await verifyFederationToken(
      token,
      { ...expected, type: 'entity-statement+jwt', requiredClaims: ['sub', 'exp', 'jwks'] },
      options,
    );
    return Object.freeze({
      issuer: expected.issuer,
      subject: expected.subject,
      issuedAt: verified.claims.iat as number,
      expiresAt: verified.expiresAt,
      keys: publicKeys(verified.claims.jwks, Math.floor(verified.expiresAt * 1000)),
      claims: verified.claims,
    });
  } catch (error) {
    if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) throw error;
    throw failure('EK_EID_FEDERATION');
  }
}
