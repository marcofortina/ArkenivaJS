// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type WebAuthnCredential,
} from '@simplewebauthn/server';
import { decodeClientDataJSON, decodeAttestationObject } from '@simplewebauthn/server/helpers';
import { KitError, type Environment } from '@arkenivajs/core';

const policyError = () =>
  new KitError({ code: 'EK_MFA_POLICY', message: 'Invalid WebAuthn policy' });
const invalid = () => new KitError({ code: 'EK_MFA_INVALID', message: 'Invalid WebAuthn proof' });
const algorithms = [-8, -7, -257];
const maxResponseBytes = 1048576;

/** Private startup snapshot; no identity or account ownership is established here. */
export interface WebAuthnDriverSettings {
  readonly rpId: string;
  readonly rpName: string;
  readonly expectedOrigins: readonly string[];
  readonly environment?: Environment;
}

function record(value: unknown): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw invalid();
}

function base64(value: unknown, maximum: number): string {
  if (
    typeof value !== 'string' ||
    value.length < 1 ||
    value.length > Math.ceil((maximum * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  )
    throw invalid();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > maximum || bytes.toString('base64url') !== value) throw invalid();
  return value;
}

function challenge(value: string): void {
  base64(value, 32);
  if (Buffer.from(value, 'base64url').length !== 32) throw invalid();
}

function snapshot(settings: WebAuthnDriverSettings) {
  const { rpId, rpName, expectedOrigins } = settings;
  const environment = settings.environment === undefined ? 'production' : settings.environment;
  if (
    !['production', 'development', 'test'].includes(environment) ||
    typeof rpId !== 'string' ||
    rpId.length > 253 ||
    rpId !== domainToASCII(rpId) ||
    rpId !== rpId.toLowerCase() ||
    isIP(rpId) !== 0 ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(rpId) ||
    rpId
      .split('.')
      .some(
        (label) =>
          label.length < 1 || label.length > 63 || label.startsWith('-') || label.endsWith('-'),
      ) ||
    (rpId === 'localhost' && environment === 'production') ||
    typeof rpName !== 'string' ||
    rpName.length < 1 ||
    rpName.length > 128 ||
    rpName.trim() !== rpName ||
    [...rpName].some(
      (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    ) ||
    !Array.isArray(expectedOrigins) ||
    expectedOrigins.length < 1 ||
    expectedOrigins.length > 64
  )
    throw policyError();
  const origins = expectedOrigins.map((origin) => {
    if (typeof origin !== 'string' || origin.length > 512) throw policyError();
    const parsed = new URL(origin);
    if (
      parsed.origin !== origin ||
      parsed.username ||
      parsed.password ||
      (parsed.hostname !== rpId && !parsed.hostname.endsWith('.' + rpId)) ||
      (parsed.protocol !== 'https:' &&
        !(parsed.protocol === 'http:' && rpId === 'localhost' && environment !== 'production'))
    )
      throw policyError();
    return origin;
  });
  if (new Set(origins).size !== origins.length) throw policyError();
  return Object.freeze({ rpId, rpName, origins: Object.freeze(origins) });
}

/** Parse bounded browser JSON before invoking the upstream verifier; no object getters are accepted. */
function response(
  text: string,
  registration: boolean,
): RegistrationResponseJSON | AuthenticationResponseJSON {
  if (
    typeof text !== 'string' ||
    text.length > maxResponseBytes ||
    Buffer.byteLength(text) > maxResponseBytes
  )
    throw invalid();
  const value: unknown = JSON.parse(text);
  record(value);
  const id = base64(value.id, 1024);
  if (value.rawId !== id || value.type !== 'public-key') throw invalid();
  record(value.response);
  record(value.clientExtensionResults);
  const client = base64(value.response.clientDataJSON, 16384);
  // Fatal UTF-8 decoding prevents malformed byte sequences from acquiring JSON semantics.
  new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(client, 'base64url'));
  const data = decodeClientDataJSON(client);
  if (
    (data.crossOrigin !== undefined && data.crossOrigin !== false) ||
    data.topOrigin !== undefined
  )
    throw invalid();
  if (registration) {
    const encoded = base64(value.response.attestationObject, 524288);
    const attestation = decodeAttestationObject(Uint8Array.from(Buffer.from(encoded, 'base64url')));
    // This primitive implements default none attestation only; device provenance is a separate policy.
    if (attestation.get('fmt') !== 'none') throw invalid();
    if (
      value.response.transports !== undefined &&
      (!Array.isArray(value.response.transports) ||
        value.response.transports.length > 16 ||
        value.response.transports.some((entry) => typeof entry !== 'string' || entry.length > 32))
    )
      throw invalid();
    return value as unknown as RegistrationResponseJSON;
  }
  base64(value.response.authenticatorData, 65536);
  base64(value.response.signature, 16384);
  if (value.response.userHandle !== undefined && value.response.userHandle !== null)
    base64(value.response.userHandle, 64);
  return value as unknown as AuthenticationResponseJSON;
}

/**
 * Upstream compatibility primitive, intentionally absent from package-root exports.
 * Success is cryptographic verification only: no challenge claim, CAS, authorization or evidence.
 */
export function createWebAuthnDriver(settings: WebAuthnDriverSettings) {
  let policy: ReturnType<typeof snapshot>;
  try {
    policy = snapshot(settings);
  } catch {
    throw policyError();
  }
  return Object.freeze({
    async registrationOptions(userHandle: Uint8Array, excluded: readonly string[] = []) {
      try {
        if (
          !(userHandle instanceof Uint8Array) ||
          userHandle.length < 1 ||
          userHandle.length > 64 ||
          !Array.isArray(excluded) ||
          excluded.length > 100
        )
          throw invalid();
        const ids = excluded.map((id) => ({ id: base64(id, 1024) }));
        return await generateRegistrationOptions({
          rpID: policy.rpId,
          rpName: policy.rpName,
          userName: 'Account',
          userID: Uint8Array.from(userHandle),
          challenge: randomBytes(32),
          timeout: 300000,
          attestationType: 'none',
          supportedAlgorithmIDs: [...algorithms],
          authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
          excludeCredentials: ids,
        });
      } catch {
        throw invalid();
      }
    },
    async authenticationOptions(allowed?: readonly string[]) {
      try {
        if (
          allowed !== undefined &&
          (!Array.isArray(allowed) || allowed.length < 1 || allowed.length > 100)
        )
          throw invalid();
        return await generateAuthenticationOptions({
          rpID: policy.rpId,
          challenge: randomBytes(32),
          timeout: 300000,
          userVerification: 'required',
          ...(allowed === undefined
            ? {}
            : { allowCredentials: allowed.map((id) => ({ id: base64(id, 1024) })) }),
        });
      } catch {
        throw invalid();
      }
    },
    async verifyRegistration(text: string, expectedChallenge: string) {
      try {
        challenge(expectedChallenge);
        const parsed = response(text, true) as RegistrationResponseJSON;
        const result = await verifyRegistrationResponse({
          response: parsed,
          expectedChallenge,
          expectedOrigin: [...policy.origins],
          expectedRPID: policy.rpId,
          requireUserPresence: true,
          requireUserVerification: true,
          supportedAlgorithmIDs: [...algorithms],
        });
        if (
          !result.verified ||
          !result.registrationInfo.userVerified ||
          result.registrationInfo.credential.id !== parsed.id
        )
          throw invalid();
        const info = result.registrationInfo;
        return {
          credential: { ...info.credential, publicKey: Uint8Array.from(info.credential.publicKey) },
          backupEligible: info.credentialDeviceType === 'multiDevice',
          backedUp: info.credentialBackedUp,
        };
      } catch {
        throw invalid();
      }
    },
    async verifyAuthentication(
      text: string,
      expectedChallenge: string,
      stored: WebAuthnCredential,
    ) {
      try {
        challenge(expectedChallenge);
        const parsed = response(text, false) as AuthenticationResponseJSON;
        if (
          base64(stored.id, 1024) !== parsed.id ||
          !(stored.publicKey instanceof Uint8Array) ||
          stored.publicKey.length < 1 ||
          stored.publicKey.length > 16384 ||
          !Number.isSafeInteger(stored.counter) ||
          stored.counter < 0 ||
          stored.counter > 0xffffffff
        )
          throw invalid();
        const credential = {
          id: stored.id,
          publicKey: Uint8Array.from(stored.publicKey),
          counter: stored.counter,
        };
        const result = await verifyAuthenticationResponse({
          response: parsed,
          expectedChallenge,
          expectedOrigin: [...policy.origins],
          expectedRPID: policy.rpId,
          credential,
          requireUserVerification: true,
        });
        if (!result.verified || !result.authenticationInfo.userVerified) throw invalid();
        const info = result.authenticationInfo;
        return {
          newCounter: info.newCounter,
          backupEligible: info.credentialDeviceType === 'multiDevice',
          backedUp: info.credentialBackedUp,
        };
      } catch {
        throw invalid();
      }
    },
  });
}
