// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { KitError } from '@arkenivajs/core';
import { freezeData } from '@arkenivajs/core/support';
import type { CryptoService } from '@arkenivajs/security-crypto';
import type { FederationAssurance, FederatedLogin } from './contracts.js';
import type { Settings } from './settings.js';
import type { FederationCall } from './runtime.js';
import type { FederationHttp } from './metadata-http.js';
import { FederationSamlRegistry } from './saml-registry.js';
import { FederationTransactions, returnPath } from './transactions.js';
import { withFederationSaml } from './saml-native.js';
import { assuranceContext } from './assurance.js';
import { failure, fields, text, url } from './validation.js';

export interface VerifiedSamlResult {
  readonly profileId: string;
  readonly issuer: string;
  readonly subject: string;
  readonly assurance: FederationAssurance;
  readonly attributes: Readonly<Record<string, readonly string[]>>;
  readonly returnPath: string;
  readonly tenantHint?: string;
  readonly expiresAt: string;
}
/** One private protocol owner binds native Redirect initiation and POST acceptance to protected state. */
export class FederationSamlLogin {
  private readonly profile;
  private readonly registry;
  private readonly transactions;
  readonly #owned = new WeakMap<VerifiedSamlResult, () => void>();
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
  async consume(call: FederationCall, input: unknown): Promise<VerifiedSamlResult> {
    try {
      call.check();
      const value = fields(input, ['transactionId', 'issuer', 'relayState', 'samlResponse']),
        transactionId = text(value.transactionId, 64),
        issuer = url(value.issuer),
        relayState = text(value.relayState, 41),
        maximum = Math.min(
          this.profile.metadata.maxBytes,
          this.settings.policy.maxInputBytes ?? Infinity,
        ),
        response = text(value.samlResponse, maximum);
      if (
        !/^[a-f0-9]{64}$/u.test(transactionId) ||
        !/^_[a-f0-9]{40}$/u.test(relayState) ||
        !this.profile.expectedIssuers.includes(issuer) ||
        Buffer.byteLength(JSON.stringify(value)) > maximum ||
        Buffer.from(response, 'base64').toString('base64') !== response
      )
        throw failure('EK_EID_FEDERATION');
      const transaction = await this.transactions.consume(call, transactionId, issuer);
      if (transaction.samlRequestId !== relayState) throw failure('EK_EID_FEDERATION');
      const rp = await this.registry.verify(call, this.profile.entityId, 'sp'),
        idp = await this.registry.verify(call, issuer, 'idp');
      const accepted = await withFederationSaml(
        call,
        this.settings,
        this.profile,
        this.registry,
        rp,
        idp,
        transaction.assurance,
        async (service) => {
          const identity = await call.step((options) =>
              service.consumeResponse(
                { inResponseTo: transaction.samlRequestId!, relayState },
                response,
                options,
              ),
            ),
            saml = fields(identity.claims.saml),
            nativeExpiry = text(saml.verificationExpiresAt, 32),
            expiresAt = Math.min(
              Date.parse(nativeExpiry),
              Date.parse(transaction.expiresAt),
              Date.parse(rp.expiresAt),
              Date.parse(idp.expiresAt),
            );
          if (
            identity.issuer !== issuer ||
            saml.transactionId !== transaction.samlRequestId ||
            saml.authnContext !== assuranceContext('spid', transaction.assurance) ||
            saml.nameIDFormat !== 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' ||
            (saml.nameQualifier !== undefined && saml.nameQualifier !== issuer) ||
            (saml.spNameQualifier !== undefined &&
              saml.spNameQualifier !== this.profile.entityId) ||
            !Number.isSafeInteger(expiresAt) ||
            new Date(Date.parse(nativeExpiry)).toISOString() !== nativeExpiry
          )
            throw failure('EK_EID_FEDERATION');
          const attribute = identity.attributes[this.profile.subjectClaim],
            subject =
              this.profile.subjectClaim === 'NameID'
                ? identity.subject
                : attribute?.length === 1
                  ? attribute[0]
                  : undefined,
            check = () => {
              this.registry.result(rp);
              this.registry.result(idp);
              if (expiresAt <= Date.now()) throw failure('EK_EID_FEDERATION');
            },
            result = freezeData({
              profileId: this.profile.profileId,
              issuer,
              subject: text(subject, 2048),
              assurance: transaction.assurance,
              attributes: identity.attributes,
              returnPath: transaction.returnPath,
              ...(transaction.tenantHint === undefined
                ? {}
                : { tenantHint: transaction.tenantHint }),
              expiresAt: new Date(expiresAt).toISOString(),
            });
          check();
          if (
            Buffer.byteLength(JSON.stringify(result)) >
            Math.min(
              this.profile.metadata.maxBytes,
              this.settings.policy.maxOutputBytes ?? Infinity,
            )
          )
            throw failure('EK_EID_FEDERATION');
          this.#owned.set(result, check);
          return result;
        },
      );
      call.check();
      return this.result(accepted);
    } catch (error) {
      if (
        error instanceof KitError &&
        [
          'EK_TIMEOUT',
          'EK_ABORTED',
          'EK_BACKEND_UNAVAILABLE',
          'EK_RESOURCE_CLOSED',
          'EK_EID_ASSURANCE',
        ].includes(error.code)
      )
        throw error;
      throw failure('EK_EID_FEDERATION');
    }
  }
  result(input: VerifiedSamlResult): VerifiedSamlResult {
    const check = this.#owned.get(input);
    if (!check) throw failure('EK_EID_FEDERATION');
    check();
    return input;
  }
}
