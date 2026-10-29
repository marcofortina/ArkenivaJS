// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isDeepStrictEqual } from 'node:util';
import { KitError } from '@arkenivajs/core';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import type { FederationHttp } from './metadata-http.js';
import { FederationMembership } from './membership.js';
import { createFederationEntityConfiguration } from './entity-configuration.js';
import { inspectConfiguration } from './statements.js';
import { failure, fields, list, text } from './validation.js';

export interface RelyingPartyEvidence {
  readonly entityId: string;
  readonly expiresAt: string;
}
const securityParameters = [
  'client_id',
  'client_registration_types',
  'application_type',
  'redirect_uris',
  'grant_types',
  'response_types',
  'jwks',
  'token_endpoint_auth_method',
  'token_endpoint_auth_signing_alg',
  'request_object_signing_alg',
  'id_token_signed_response_alg',
  'id_token_encrypted_response_alg',
  'id_token_encrypted_response_enc',
  'userinfo_signed_response_alg',
  'userinfo_encrypted_response_alg',
  'userinfo_encrypted_response_enc',
];
function normalized(value: unknown, parameter: string) {
  if (value === undefined) return undefined;
  const captured: unknown = JSON.parse(JSON.stringify(value));
  if (parameter !== 'jwks') return captured;
  const keys = list(fields(captured, ['keys']).keys, 32).map((item) => fields(item));
  return { keys: [...keys].sort((left, right) => text(left.kid).localeCompare(text(right.kid))) };
}
/** Current local RP participation is separate from OP trust and from external certification. */
export class FederationRelyingParty {
  private readonly profile;
  private readonly membership;
  readonly #owned = new WeakMap<RelyingPartyEvidence, () => void>();
  constructor(
    private readonly settings: Settings,
    profileId: string,
    http: Pick<FederationHttp, 'statement' | 'trustMarkStatus'>,
  ) {
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId);
    if (!profile?.oidcRegistration || profile.protocol !== 'oidc-federation')
      throw failure('EK_EID_PROFILE');
    this.profile = profile;
    this.membership = new FederationMembership(
      { ...profile, expectedIssuers: [profile.entityId] },
      http,
      'openid_relying_party',
    );
  }
  async verify(call: FederationCall): Promise<RelyingPartyEvidence> {
    try {
      call.check();
      const configuration = await createFederationEntityConfiguration(
          call,
          this.settings,
          this.profile.profileId,
        ),
        proof = await this.membership.verify(call, configuration),
        original = fields(
          fields(
            inspectConfiguration(configuration, this.profile.metadata.maxBytes).claims.metadata,
          ).openid_relying_party,
        ),
        resolved = fields(proof.metadata.openid_relying_party);
      if (proof.subject !== this.profile.entityId) throw failure('EK_EID_FEDERATION');
      for (const name of securityParameters)
        if (!isDeepStrictEqual(normalized(original[name], name), normalized(resolved[name], name)))
          throw failure('EK_EID_FEDERATION');
      const check = () => {
          this.membership.nodes(proof);
          if (Date.now() / 1000 >= proof.expiresAt) throw failure('EK_EID_FEDERATION');
        },
        result = Object.freeze({
          entityId: this.profile.entityId,
          expiresAt: new Date(proof.expiresAt * 1000).toISOString(),
        });
      check();
      call.check();
      this.#owned.set(result, check);
      return result;
    } catch (error) {
      if (
        error instanceof KitError &&
        ['EK_TIMEOUT', 'EK_ABORTED', 'EK_BACKEND_UNAVAILABLE', 'EK_RESOURCE_CLOSED'].includes(
          error.code,
        )
      )
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
  check(input: RelyingPartyEvidence) {
    const check = this.#owned.get(input);
    if (!check) throw failure('EK_EID_FEDERATION');
    check();
  }
}
