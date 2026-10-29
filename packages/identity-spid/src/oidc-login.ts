// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import {
  Configuration,
  PrivateKeyJwt,
  buildAuthorizationUrlWithJAR,
  calculatePKCECodeChallenge,
  modifyAssertion,
} from 'openid-client';
import { KitError } from '@arkenivajs/core';
import type { CryptoService } from '@arkenivajs/security-crypto';
import type { FederationAssurance, FederatedLogin } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import type { FederationHttp } from './metadata-http.js';
import { FederationMembership } from './membership.js';
import { FederationTransactions, returnPath } from './transactions.js';
import { configurationEndpoint } from './resolver.js';
import { loadFederationSigningKey } from './signing.js';
import { inspectTrustMark } from './statements.js';
import { failure, fields, list, method, text, url } from './validation.js';

const contexts = {
  'spid-l1': 'https://www.spid.gov.it/SpidL1',
  'spid-l2': 'https://www.spid.gov.it/SpidL2',
  'spid-l3': 'https://www.spid.gov.it/SpidL3',
} as const;
/** Private protocol composition; callback verification and canonical identity mapping remain separate. */
export class FederationOidcLogin {
  private readonly profile;
  private readonly membership;
  private readonly transactions;
  private readonly read;
  constructor(
    private readonly settings: Settings,
    profileId: string,
    http: Pick<FederationHttp, 'statement' | 'trustMarkStatus'>,
    crypto: CryptoService,
  ) {
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId);
    if (!profile || profile.protocol !== 'oidc-federation' || !profile.oidcRegistration)
      throw failure('EK_EID_PROFILE');
    this.profile = profile;
    this.membership = new FederationMembership(profile, http);
    this.transactions = new FederationTransactions(settings, profileId, crypto);
    this.read = method<FederationHttp['statement']>(http, 'statement');
  }
  async begin(
    call: FederationCall,
    input: {
      issuer: string;
      assurance: FederationAssurance;
      returnPath: string;
      tenantHint?: string;
    },
  ): Promise<FederatedLogin> {
    try {
      call.check();
      const value = fields(input, ['issuer', 'assurance', 'returnPath', 'tenantHint']),
        issuer = url(value.issuer),
        path = returnPath(value.returnPath),
        assurance = value.assurance as keyof typeof contexts,
        tenantHint = value.tenantHint === undefined ? undefined : text(value.tenantHint),
        registration = this.profile.oidcRegistration!;
      if (
        !this.profile.expectedIssuers.includes(issuer) ||
        !this.profile.allowedAssurance.includes(assurance) ||
        !Object.hasOwn(contexts, assurance)
      )
        throw failure('EK_EID_ASSURANCE');
      if (
        Buffer.byteLength(
          JSON.stringify({
            issuer,
            assurance,
            returnPath: path,
            ...(tenantHint ? { tenantHint } : {}),
          }),
        ) > Math.min(this.settings.policy.maxInputBytes ?? Infinity, this.profile.metadata.maxBytes)
      )
        throw failure('EK_EID_FEDERATION');
      if (
        registration.trustMarks.some(
          (mark) =>
            (inspectTrustMark(mark, this.profile.metadata.maxBytes).claims.exp as number) <=
            Date.now() / 1000,
        )
      )
        throw failure('EK_EID_FEDERATION');
      const encoded = await call.step((options) =>
          this.read(configurationEndpoint(issuer), undefined, options),
        ),
        proof = await this.membership.verify(call, encoded),
        metadata = fields(proof.metadata.openid_provider),
        supported = (name: string, expected: string) => {
          if (!list(metadata[name]).includes(expected)) throw failure('EK_EID_FEDERATION');
        };
      if (proof.subject !== issuer || metadata.issuer !== issuer)
        throw failure('EK_EID_FEDERATION');
      supported('response_types_supported', 'code');
      supported('scopes_supported', 'openid');
      supported('code_challenge_methods_supported', 'S256');
      supported('request_object_signing_alg_values_supported', registration.signingAlgorithm);
      supported('acr_values_supported', contexts[assurance]);
      supported('client_registration_types_supported', 'automatic');
      const automaticRequest =
        metadata.request_authentication_methods_supported === undefined
          ? false
          : list(fields(metadata.request_authentication_methods_supported).ar).includes(
              'request_object',
            );
      if (
        (metadata.request_parameter_supported !== undefined &&
          typeof metadata.request_parameter_supported !== 'boolean') ||
        metadata.request_parameter_supported === false ||
        (metadata.request_parameter_supported !== true && !automaticRequest)
      )
        throw failure('EK_EID_FEDERATION');
      if (registration.requestedClaims.length && metadata.claims_parameter_supported !== true)
        throw failure('EK_EID_FEDERATION');
      const authorization = url(metadata.authorization_endpoint),
        signer = await loadFederationSigningKey(
          call,
          this.settings,
          this.profile.profileId,
          registration.signingAlgorithm,
        ),
        config = new Configuration(
          { issuer, authorization_endpoint: authorization },
          this.profile.clientId!,
          {
            token_endpoint_auth_signing_alg: signer.algorithm,
          },
          PrivateKeyJwt({ key: signer.key, kid: signer.kid }),
        ),
        transaction = await this.transactions.create(call, {
          issuer,
          assurance,
          returnPath: path,
          ...(tenantHint ? { tenantHint } : {}),
        }),
        challenge = await call.step(() => calculatePKCECodeChallenge(transaction.verifier)),
        claims = Object.fromEntries(registration.requestedClaims.map((name) => [name, null])),
        parameters = {
          response_type: 'code',
          scope: 'openid',
          redirect_uri: this.profile.redirectUri,
          state: transaction.transactionId,
          nonce: transaction.nonce,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          acr_values: contexts[assurance],
          prompt: 'consent',
          ...(registration.requestedClaims.length
            ? { claims: JSON.stringify({ userinfo: claims }) }
            : {}),
        };
      let expiresAt = Math.floor(
        Math.min(
          Date.parse(transaction.expiresAt) / 1000,
          proof.expiresAt,
          signer.expiresAt / 1000,
        ),
      );
      signer.check();
      this.membership.nodes(proof);
      const result = await call.step(() =>
        buildAuthorizationUrlWithJAR(
          config,
          parameters,
          { key: signer.key, kid: signer.kid },
          {
            [modifyAssertion]: (_header, payload) => {
              expiresAt = Math.min(expiresAt, payload.exp as number);
              if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() / 1000)
                throw failure('EK_EID_FEDERATION');
              payload.exp = expiresAt;
            },
          },
        ),
      );
      for (const name of [
        'scope',
        'response_type',
        'code_challenge',
        'code_challenge_method',
      ] as const)
        result.searchParams.set(name, parameters[name]);
      signer.check();
      this.membership.nodes(proof);
      call.check();
      if (
        Buffer.byteLength(result.href) >
          Math.min(
            this.settings.policy.maxOutputBytes ?? Infinity,
            this.profile.metadata.maxBytes,
          ) ||
        Date.now() / 1000 >= expiresAt
      )
        throw failure('EK_EID_FEDERATION');
      return Object.freeze({
        transactionId: transaction.transactionId,
        redirectUrl: result.href,
        expiresAt: new Date(expiresAt * 1000).toISOString(),
      });
    } catch (error) {
      if (
        error instanceof KitError &&
        ['EK_TIMEOUT', 'EK_ABORTED', 'EK_EID_ASSURANCE'].includes(error.code)
      )
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
}
