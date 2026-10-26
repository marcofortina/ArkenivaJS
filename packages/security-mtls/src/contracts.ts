// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

/** Approved credential references and explicit peer authorization, independent of TLS parsing. */
export interface TlsProfile {
  readonly trustRootsRef: string;
  readonly certRef: string;
  readonly keyRef: string;
  readonly allowedIdentities: readonly string[];
  readonly minTlsVersion?: 'TLSv1.2' | 'TLSv1.3';
  readonly alpnProtocols?: readonly string[];
  readonly revocation: 'crl-required' | 'ocsp-required' | 'approved-online-checker';
}
/** Owned byte material; this shape must be explicitly converted before passing it to Node TLS. */
export interface TlsMaterial {
  readonly ca: readonly Uint8Array[];
  readonly cert: Uint8Array;
  readonly key: Uint8Array;
  readonly minVersion: 'TLSv1.2' | 'TLSv1.3';
  readonly ALPNProtocols?: readonly string[];
}
/** Client material always verifies the configured server hostname and trust roots. */
export interface TlsClientOptions extends TlsMaterial {
  readonly rejectUnauthorized: true;
  readonly servername: string;
}
/** Server material requires and verifies a client certificate before policy authorization. */
export interface TlsServerOptions extends TlsMaterial {
  readonly requestCert: true;
  readonly rejectUnauthorized: true;
}
/** Explicit Node-compatible PEM fields; all key strings are confidential application material. */
export interface NativeTlsOptions {
  readonly ca: string[];
  readonly cert: string;
  readonly key: string;
  readonly minVersion: 'TLSv1.2' | 'TLSv1.3';
  readonly ALPNProtocols?: string[];
  readonly rejectUnauthorized: true;
  readonly requestCert?: true;
  readonly servername?: string;
}
/** Trusted verified peer metadata; never a proxy-header or caller-supplied authentication claim. */
export interface VerifiedPeerIdentity {
  readonly uriSans: readonly string[];
  readonly dnsSans: readonly string[];
  readonly certificateFingerprintSha256: string;
  readonly issuer: string;
  readonly notAfter: string;
}
/** A root reference and identity catalogue must match an approved bootstrap profile. */
export interface TlsTrustVerificationPolicy {
  readonly trustRootsRef: string;
  readonly allowedIdentities: readonly string[];
  readonly hostname?: string;
  readonly revocation: 'crl-required' | 'ocsp-required' | 'approved-online-checker';
}
/** Independently reviewed complete path, purpose and revocation checking with bounded I/O. */
export interface MtlsTrustProvider {
  verifyChainAndRevocation(
    input: { peerDer: Uint8Array; policy: TlsTrustVerificationPolicy; now: string },
    options?: OperationOptions,
  ): Promise<VerifiedPeerIdentity>;
}
/** Resolve only the approved profile's references through application-owned secret infrastructure. */
export interface MtlsCredentialProvider {
  load(profile: TlsProfile, options?: OperationOptions): Promise<TlsMaterial>;
}
/** Finite admission and payload limits; providers ignoring cancellation retain their slot. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Explicit reload and provider injection; no ambient process-wide credential lookup. */
export interface MtlsPluginSettings {
  readonly profiles: Readonly<Record<string, TlsProfile>>;
  readonly credentialProvider: MtlsCredentialProvider;
  readonly trustProvider: MtlsTrustProvider;
  readonly reloadMode: 'explicit';
  readonly policy: BoundedRuntimePolicy;
}
/** Material preparation and asynchronous peer policy are separate mandatory trust stages. */
export interface MtlsService {
  createClientOptions(
    profile: TlsProfile,
    servername: string,
    options?: OperationOptions,
  ): Promise<TlsClientOptions>;
  createServerOptions(profile: TlsProfile, options?: OperationOptions): Promise<TlsServerOptions>;
  toNodeClientOptions(options: TlsClientOptions): NativeTlsOptions;
  toNodeServerOptions(options: TlsServerOptions): NativeTlsOptions;
  verifyPeer(
    peer: Uint8Array,
    policy: TlsTrustVerificationPolicy,
    options?: OperationOptions,
  ): Promise<VerifiedPeerIdentity>;
  reloadCertificates(options?: OperationOptions): Promise<void>;
}
