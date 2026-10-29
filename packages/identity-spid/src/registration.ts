// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { freezeData } from '@arkenivajs/core/support';
import validator from 'validator';
import type {
  FederationEncryptionPolicy,
  FederationOidcRegistration,
  FederationSignatureAlgorithm,
} from './contracts.js';
import { inspectTrustMark } from './statements.js';
import { failure, fields, list, text, url } from './validation.js';

function signature(input: unknown): FederationSignatureAlgorithm {
  if (
    !['RS256', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512'].includes(
      input as string,
    )
  )
    throw failure();
  return input as FederationSignatureAlgorithm;
}
function encryption(input: unknown): FederationEncryptionPolicy {
  const value = fields(input, ['algorithm', 'encryption']);
  if (
    !['RSA-OAEP', 'RSA-OAEP-256'].includes(value.algorithm as string) ||
    !['A128CBC-HS256', 'A256CBC-HS512'].includes(value.encryption as string)
  )
    throw failure();
  return Object.freeze({
    algorithm: value.algorithm as FederationEncryptionPolicy['algorithm'],
    encryption: value.encryption as FederationEncryptionPolicy['encryption'],
  });
}
function strings(input: unknown, convert = text, maximum = 64, allowEmpty = false) {
  const result = list(input, maximum, allowEmpty).map((item) => convert(item));
  if (new Set(result).size !== result.length) throw failure();
  return Object.freeze(result);
}
function name(input: unknown) {
  if (
    typeof input !== 'string' ||
    !input.trim() ||
    Buffer.byteLength(input) > 512 ||
    Buffer.from(input).toString() !== input ||
    [...input].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)
  )
    throw failure();
  return input;
}
/** Capture typed RP registration data without fetching resources or trusting mark signatures. */
export function captureRegistration(
  input: unknown,
  entity: string,
  signingKeyRef: string,
  maxBytes: number,
): FederationOidcRegistration {
  try {
    const value = fields(input, [
        'authorityHints',
        'trustMarks',
        'organization',
        'signingAlgorithm',
        'idTokenSigningAlgorithm',
        'userInfoSigningAlgorithm',
        'decryptionKeyRef',
        'idTokenEncryption',
        'userInfoEncryption',
        'requestedClaims',
        'approvedProtocolEndpoints',
      ]),
      organization = fields(value.organization, [
        'organizationName',
        'homepageUri',
        'policyUri',
        'contacts',
        'resolveEndpoint',
        'logoUri',
      ]);
    const decryptionKeyRef = text(value.decryptionKeyRef);
    if (decryptionKeyRef === signingKeyRef) throw failure();
    const contacts = strings(organization.contacts, name);
    if (contacts.some((contact) => !validator.isEmail(contact))) throw failure();
    const logoUri = organization.logoUri === undefined ? undefined : url(organization.logoUri);
    if (logoUri && !new URL(logoUri).pathname.toLowerCase().endsWith('.svg')) throw failure();
    let used = 0,
      relyingPartyMark = false;
    const trustMarks = list(value.trustMarks, 32).map((item) => {
      if (typeof item !== 'string' || (used += Buffer.byteLength(item)) > maxBytes) throw failure();
      const mark = inspectTrustMark(item, maxBytes);
      const now = Date.now() / 1000;
      if (
        mark.subject !== entity ||
        !Number.isSafeInteger(mark.claims.iat) ||
        (mark.claims.iat as number) < 0 ||
        (mark.claims.iat as number) > now ||
        !Number.isSafeInteger(mark.claims.exp) ||
        (mark.claims.exp as number) <= now ||
        (mark.claims.exp as number) <= (mark.claims.iat as number)
      )
        throw failure();
      if (new URL(mark.type).pathname.split('/')[1] === 'openid_relying_party')
        relyingPartyMark = true;
      return item;
    });
    if (!relyingPartyMark || new Set(trustMarks).size !== trustMarks.length) throw failure();
    const requestedClaims = strings(value.requestedClaims, (item) => text(item, 2048), 64, true);
    if (requestedClaims.some((claim) => ['__proto__', 'prototype', 'constructor'].includes(claim)))
      throw failure();
    const authorityHints = strings(value.authorityHints, url);
    if (authorityHints.includes(entity)) throw failure();
    const result = freezeData({
      authorityHints,
      trustMarks,
      organization: {
        organizationName: name(organization.organizationName),
        homepageUri: url(organization.homepageUri),
        policyUri: url(organization.policyUri),
        contacts,
        resolveEndpoint: url(organization.resolveEndpoint),
        ...(logoUri ? { logoUri } : {}),
      },
      signingAlgorithm: signature(value.signingAlgorithm),
      idTokenSigningAlgorithm: signature(value.idTokenSigningAlgorithm),
      userInfoSigningAlgorithm: signature(value.userInfoSigningAlgorithm),
      decryptionKeyRef,
      ...(value.idTokenEncryption === undefined
        ? {}
        : { idTokenEncryption: encryption(value.idTokenEncryption) }),
      userInfoEncryption: encryption(value.userInfoEncryption),
      requestedClaims,
      ...(value.approvedProtocolEndpoints === undefined
        ? {}
        : {
            approvedProtocolEndpoints: strings(value.approvedProtocolEndpoints, url),
          }),
    });
    if (Buffer.byteLength(JSON.stringify(result)) > maxBytes) throw failure();
    return result;
  } catch {
    throw failure();
  }
}
