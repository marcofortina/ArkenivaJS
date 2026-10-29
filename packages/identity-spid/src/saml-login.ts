// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { CryptoService } from '@arkenivajs/security-crypto';
import type { FederationAssurance, FederatedLogin } from './contracts.js';
import type { Settings } from './settings.js';
import type { FederationCall } from './runtime.js';
import type { FederationHttp } from './metadata-http.js';
import { FederationSamlRegistry } from './saml-registry.js';
import { FederationTransactions, returnPath } from './transactions.js';
import { withFederationSaml } from './saml-native.js';
import { failure, fields, text, url } from './validation.js';

/** Private Redirect initiation through the existing native SAML adapter; callback acceptance stays separate. */
export class FederationSamlLogin {
  private readonly profile;
  private readonly registry;
  private readonly transactions;
  constructor(
    private readonly settings: Settings,
    profileId: string,
    http: Pick<FederationHttp, 'samlMetadata' | 'samlRegistryStatus'>,
    crypto: CryptoService,
  ) {
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId);
    if (!profile || profile.protocol !== 'saml2' || !profile.samlRegistration?.registrySources)
      throw failure('EK_EID_PROFILE');
    this.profile = profile;
    this.registry = new FederationSamlRegistry(profile, http);
    this.transactions = new FederationTransactions(settings, profileId, crypto);
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
    const value = fields(input, ['issuer', 'assurance', 'returnPath', 'tenantHint']),
      issuer = url(value.issuer),
      assurance = value.assurance as FederationAssurance,
      path = returnPath(value.returnPath),
      tenantHint = value.tenantHint === undefined ? undefined : text(value.tenantHint);
    if (
      !this.profile.expectedIssuers.includes(issuer) ||
      !this.profile.allowedAssurance.includes(assurance)
    )
      throw failure('EK_EID_ASSURANCE');
    if (
      Buffer.byteLength(JSON.stringify([issuer, assurance, path, tenantHint ?? null])) >
      (this.settings.policy.maxInputBytes ?? this.profile.metadata.maxBytes)
    )
      throw failure('EK_EID_FEDERATION');
    const rp = await this.registry.verify(call, this.profile.entityId, 'sp'),
      idp = await this.registry.verify(call, issuer, 'idp');
    return withFederationSaml(
      call,
      this.settings,
      this.profile,
      this.registry,
      rp,
      idp,
      assurance,
      async (service) => {
        const request = await call.step((options) =>
          service.beginLogin({ returnPath: '/' }, options),
        );
        if (request.binding !== 'redirect') throw failure('EK_EID_PROFILE');
        const transaction = await this.transactions.create(call, {
          issuer,
          assurance,
          returnPath: path,
          ...(tenantHint === undefined ? {} : { tenantHint }),
          samlRequestId: request.requestId,
        });
        const expiresAt = Math.min(
          Date.parse(request.expiresAt),
          Date.parse(transaction.expiresAt),
          Date.parse(rp.expiresAt),
          Date.parse(idp.expiresAt),
        );
        if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now())
          throw failure('EK_EID_FEDERATION');
        const result = Object.freeze({
          transactionId: transaction.transactionId,
          redirectUrl: request.redirectUrl,
          expiresAt: new Date(expiresAt).toISOString(),
        });
        if (
          Buffer.byteLength(JSON.stringify(result)) > (this.settings.policy.maxOutputBytes ?? 65536)
        )
          throw failure('EK_EID_FEDERATION');
        return result;
      },
    );
  }
}
