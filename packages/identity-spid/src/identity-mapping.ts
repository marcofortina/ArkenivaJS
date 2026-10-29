// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import type { VerifiedTenantContext } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { FederatedIdentity } from './contracts.js';
import type { FederationCall } from './runtime.js';
import type { Settings } from './settings.js';
import { FederationOidcCallback } from './oidc-callback.js';
import type { VerifiedOidcResult } from './oidc-callback.js';
import { FederationSamlLogin } from './saml-login.js';
import type { VerifiedSamlResult } from './saml-login.js';
import { failure, fields, method } from './validation.js';

export interface FederationTenantVerifier {
  isVerifiedTenant(value: unknown): value is VerifiedTenantContext;
}
/** Map owned upstream evidence through the captured application policy and current AuthService. */
export class FederationIdentityMapping {
  private readonly profile;
  private readonly result;
  private readonly verified;
  constructor(
    private readonly settings: Settings,
    profileId: string,
    callback: FederationOidcCallback | FederationSamlLogin,
    auth: FederationTenantVerifier,
  ) {
    const profile = settings.profiles.find((candidate) => candidate.profileId === profileId);
    const oidc = callback instanceof FederationOidcCallback,
      saml = callback instanceof FederationSamlLogin;
    if (!profile || (profile.protocol === 'oidc-federation' ? !oidc : !saml))
      throw failure('EK_EID_PROFILE');
    this.profile = profile;
    this.result = oidc
      ? FederationOidcCallback.prototype.result.bind(callback)
      : FederationSamlLogin.prototype.result.bind(callback as FederationSamlLogin);
    this.verified = method<FederationTenantVerifier['isVerifiedTenant']>(auth, 'isVerifiedTenant');
  }
  async map(
    call: FederationCall,
    input: VerifiedOidcResult | VerifiedSamlResult,
  ): Promise<FederatedIdentity> {
    try {
      call.check();
      const upstream = this.result(input);
      if (upstream.profileId !== this.profile.profileId) throw failure('EK_EID_FEDERATION');
      const mapping = this.settings.identityMappers[this.profile.tenantMappingId];
      if (!mapping) throw failure('EK_EID_PROFILE');
      const mapped = fields(
        await call.step((options) =>
          mapping.map(
            Object.freeze({
              profileId: this.profile.profileId,
              system: this.profile.system,
              issuer: upstream.issuer,
              subject: upstream.subject,
              assurance: upstream.assurance,
              attributes: upstream.attributes,
            }),
            options,
          ),
        ),
        ['issuer', 'subject', 'tenant', 'assurance'],
      );
      this.result(input);
      if (this.verified(mapped.tenant) !== true) throw failure('EK_EID_FEDERATION');
      const tenant = mapped.tenant,
        identity = tenant.identity;
      if (
        mapped.issuer !== identity.issuer ||
        mapped.subject !== identity.subject ||
        mapped.assurance !== upstream.assurance ||
        (upstream.tenantHint !== undefined && upstream.tenantHint !== tenant.tenantId)
      )
        throw failure('EK_EID_FEDERATION');
      const authorized = fields(
        await call.step((options) =>
          this.settings.authority.require(
            this.profile.system + '.consume_authentication',
            { issuer: identity.issuer, subject: identity.subject, tenant },
            { tenant },
            options,
          ),
        ),
        ['issuer', 'subject', 'tenant'],
      );
      if (
        authorized.issuer !== identity.issuer ||
        authorized.subject !== identity.subject ||
        (authorized.tenant !== undefined &&
          (this.verified(authorized.tenant) !== true ||
            authorized.tenant.tenantId !== tenant.tenantId ||
            authorized.tenant.identity.issuer !== identity.issuer ||
            authorized.tenant.identity.subject !== identity.subject))
      )
        throw failure('EK_EID_FEDERATION');
      this.result(input);
      if (this.verified(tenant) !== true) throw failure('EK_EID_FEDERATION');
      call.check();
      const result = freezeData({
        issuer: identity.issuer,
        subject: identity.subject,
        audience: identity.audience,
        scopes: identity.scopes,
        claims: identity.claims,
        system: this.profile.system,
        federationAssurance: upstream.assurance,
        attributes: upstream.attributes,
        profileId: this.profile.profileId,
        profileVersion: '1.0.0' as const,
      });
      if (
        Buffer.byteLength(JSON.stringify(result)) >
        Math.min(this.profile.metadata.maxBytes, this.settings.policy.maxOutputBytes ?? Infinity)
      )
        throw failure('EK_EID_FEDERATION');
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
}
