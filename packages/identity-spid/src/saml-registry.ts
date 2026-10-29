// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FederationProfileV1 } from './contracts.js';
import type { FederationHttp } from './metadata-http.js';
import type { FederationCall } from './runtime.js';
import { FederationSamlSignatures } from './saml-signatures.js';
import { captureProfile } from './settings.js';
import { failure, method, url } from './validation.js';

type Evidence = Awaited<ReturnType<FederationSamlSignatures['verifyRegistry']>>;

/** Fetch both representations afresh and bind technical participation to one approved profile owner. */
export class FederationSamlRegistry {
  private readonly profile: FederationProfileV1;
  private readonly signatures: FederationSamlSignatures;
  private readonly metadata: FederationHttp['samlMetadata'];
  private readonly status: FederationHttp['samlRegistryStatus'];
  readonly #owned = new WeakMap<
    Evidence,
    { native: Evidence; expiresAt: number; issuer: string; generation: symbol | undefined }
  >();
  readonly #invalidations = new Map<string, symbol>();
  readonly #bytes = new WeakMap<FederationCall, number>();
  constructor(
    profile: FederationProfileV1,
    http: Pick<FederationHttp, 'samlMetadata' | 'samlRegistryStatus'>,
  ) {
    this.profile = captureProfile(profile, 'spid');
    if (this.profile.protocol !== 'saml2' || !this.profile.samlRegistration?.registrySources)
      throw failure('EK_EID_PROFILE');
    this.signatures = new FederationSamlSignatures(this.profile);
    this.metadata = method<FederationHttp['samlMetadata']>(http, 'samlMetadata');
    this.status = method<FederationHttp['samlRegistryStatus']>(http, 'samlRegistryStatus');
  }
  private consume(call: FederationCall, document: string): string {
    if (typeof document !== 'string') throw failure('EK_EID_FEDERATION');
    const bytes = (this.#bytes.get(call) ?? 0) + Buffer.byteLength(document);
    this.#bytes.set(call, bytes);
    if (bytes > Math.min(this.profile.metadata.maxBytes, 65536)) throw failure('EK_EID_FEDERATION');
    return document;
  }
  async verify(call: FederationCall, entity: string, role: 'idp' | 'sp'): Promise<Evidence> {
    call.check();
    const issuer = url(entity),
      began = Date.now(),
      source = this.profile.samlRegistration!.registrySources![issuer];
    if (
      !source ||
      !['idp', 'sp'].includes(role) ||
      (role === 'sp'
        ? issuer !== this.profile.entityId
        : !this.profile.expectedIssuers.includes(issuer))
    )
      throw failure('EK_EID_FEDERATION');
    const generation = this.#invalidations.get(issuer);
    try {
      const xml = this.consume(
          call,
          await call.step((options) => this.metadata(source.metadataEndpoint, options)),
        ),
        status = this.consume(
          call,
          await call.step((options) => this.status(source.statusEndpoint, options)),
        ),
        native = await this.signatures.verifyRegistry(call, xml, status, role);
      if (native.issuer !== issuer || this.#invalidations.get(issuer) !== generation)
        throw failure('EK_EID_FEDERATION');
      const expiresAt = Math.min(
          Date.parse(native.expiresAt),
          began + this.profile.metadata.refreshIntervalSeconds * 1000,
        ),
        evidence = Object.freeze({ ...native, expiresAt: new Date(expiresAt).toISOString() });
      if (
        Buffer.byteLength(JSON.stringify(evidence)) >
        Math.min(this.profile.metadata.maxBytes, 65536)
      )
        throw failure('EK_EID_FEDERATION');
      call.check();
      this.#owned.set(evidence, { native, expiresAt, issuer, generation });
      this.result(evidence);
      return evidence;
    } catch (error) {
      this.#invalidations.set(issuer, Symbol());
      throw error;
    }
  }
  result(input: unknown): Evidence {
    const owned = this.#owned.get(input as Evidence);
    if (
      !owned ||
      owned.expiresAt <= Date.now() ||
      this.#invalidations.get(owned.issuer) !== owned.generation
    )
      throw failure('EK_EID_FEDERATION');
    this.signatures.registryResult(owned.native);
    return input as Evidence;
  }
}
