// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { SignJWT } from 'jose';
import { KitError } from '@arkenivajs/core';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import { loadFederationSigningKey } from './signing.js';
import { loadFederationDecryptionKey } from './decryption.js';
import { inspectTrustMark } from './statements.js';
import { failure } from './validation.js';

/** Sign the configured RP's public registration; publication does not establish accreditation. */
export async function createFederationEntityConfiguration(
  call: FederationCall,
  settings: Settings,
  profileId: string,
): Promise<string> {
  try {
    call.check();
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId),
      registration = profile?.oidcRegistration;
    if (!profile || profile.protocol !== 'oidc-federation' || !registration)
      throw failure('EK_EID_PROFILE');
    const signing = await loadFederationSigningKey(
        call,
        settings,
        profileId,
        registration.signingAlgorithm,
      ),
      decryption = await loadFederationDecryptionKey(call, settings, profileId);
    if (signing.kid === decryption.publicJwk.kid) throw failure('EK_EID_FEDERATION');
    const now = Math.floor(Date.now() / 1000),
      marks = registration.trustMarks.map((token) =>
        inspectTrustMark(token, profile.metadata.maxBytes),
      ),
      expiresAt = Math.floor(
        Math.min(
          now + profile.metadata.refreshIntervalSeconds,
          signing.expiresAt / 1000,
          decryption.expiresAt / 1000,
          ...marks.map((mark) => mark.claims.exp as number),
        ),
      );
    if (
      !Number.isSafeInteger(expiresAt) ||
      expiresAt <= now ||
      marks.some((mark) => mark.subject !== profile.entityId || (mark.claims.iat as number) > now)
    )
      throw failure('EK_EID_FEDERATION');
    const organization = registration.organization,
      relyingParty = {
        client_id: profile.clientId,
        client_registration_types: ['automatic'],
        application_type: 'web',
        redirect_uris: [profile.redirectUri],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        jwks: { keys: [signing.publicJwk, decryption.publicJwk] },
        token_endpoint_auth_method: 'private_key_jwt',
        token_endpoint_auth_signing_alg: registration.signingAlgorithm,
        request_object_signing_alg: registration.signingAlgorithm,
        id_token_signed_response_alg: registration.idTokenSigningAlgorithm,
        ...(registration.idTokenEncryption
          ? {
              id_token_encrypted_response_alg: registration.idTokenEncryption.algorithm,
              id_token_encrypted_response_enc: registration.idTokenEncryption.encryption,
            }
          : {}),
        userinfo_signed_response_alg: registration.userInfoSigningAlgorithm,
        userinfo_encrypted_response_alg: registration.userInfoEncryption.algorithm,
        userinfo_encrypted_response_enc: registration.userInfoEncryption.encryption,
      },
      claims = {
        jwks: { keys: [signing.publicJwk] },
        authority_hints: registration.authorityHints,
        trust_marks: marks.map((mark, index) => ({
          ...(mark.claims.id === undefined ? { trust_mark_type: mark.type } : { id: mark.type }),
          trust_mark: registration.trustMarks[index]!,
        })),
        metadata: {
          federation_entity: {
            organization_name: organization.organizationName,
            homepage_uri: organization.homepageUri,
            policy_uri: organization.policyUri,
            contacts: organization.contacts,
            federation_resolve_endpoint: organization.resolveEndpoint,
            ...(organization.logoUri ? { logo_uri: organization.logoUri } : {}),
          },
          openid_relying_party: relyingParty,
        },
      },
      maximum = Math.min(profile.metadata.maxBytes, settings.policy.maxOutputBytes ?? Infinity);
    if (Buffer.byteLength(JSON.stringify(claims)) > maximum) throw failure('EK_EID_FEDERATION');
    signing.check();
    decryption.check();
    const result = await call.step(() =>
      new SignJWT(claims)
        .setProtectedHeader({
          alg: signing.algorithm,
          kid: signing.kid,
          typ: 'entity-statement+jwt',
        })
        .setIssuer(profile.entityId)
        .setSubject(profile.entityId)
        .setIssuedAt(now)
        .setExpirationTime(expiresAt)
        .sign(signing.key),
    );
    signing.check();
    decryption.check();
    call.check();
    if (Date.now() / 1000 >= expiresAt || Buffer.byteLength(result) > maximum)
      throw failure('EK_EID_FEDERATION');
    return result;
  } catch (error) {
    if (error instanceof KitError && ['EK_TIMEOUT', 'EK_ABORTED'].includes(error.code)) throw error;
    throw failure('EK_EID_FEDERATION');
  }
}
