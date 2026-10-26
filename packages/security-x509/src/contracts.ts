// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions } from '@arkenivajs/core';

/** Public certificate metadata; parsing establishes no trust or application authorization. */
export interface X509Info {
  readonly subject: string;
  readonly issuer: string;
  readonly dnsSans: readonly string[];
  readonly uriSans: readonly string[];
  readonly notBefore: string;
  readonly notAfter: string;
  readonly fingerprintSha256: string;
  readonly publicKeyAlgorithm: string;
}
/** Lowercase hexadecimal digests; SHA512 may be absent for externally supplied metadata. */
export interface CertificateFingerprints {
  readonly sha256: string;
  readonly sha512?: string;
}
/** Only the exact trusted status establishes successful configured chain verification. */
export interface CertificateValidation {
  readonly status: 'trusted' | 'untrusted' | 'expired' | 'revoked' | 'indeterminate';
  readonly reasons: readonly string[];
}
/** Explicit trust-store identity and identity/revocation requirements for a trusted backend. */
export interface TlsTrustVerificationPolicy {
  readonly trustRootsRef: string;
  readonly allowedIdentities: readonly string[];
  readonly hostname?: string;
  readonly revocation: 'crl-required' | 'ocsp-required' | 'approved-online-checker';
}
/** Independent verified peer metadata, bound to the actual certificate fingerprint. */
export interface VerifiedPeerIdentity {
  readonly uriSans: readonly string[];
  readonly dnsSans: readonly string[];
  readonly certificateFingerprintSha256: string;
  readonly issuer: string;
  readonly notAfter: string;
}
/** Application-configured complete PKI/revocation verification, never merely a signature check. */
export interface MtlsTrustProvider {
  verifyChainAndRevocation(
    input: { peerDer: Uint8Array; policy: TlsTrustVerificationPolicy; now: string },
    options?: OperationOptions,
  ): Promise<VerifiedPeerIdentity>;
}
/** Finite operation admission and resource limits; saturation creates no hidden queue. */
export interface BoundedRuntimePolicy {
  readonly maxConcurrent: number;
  readonly timeoutMs: number;
  readonly maxInputBytes?: number;
  readonly maxOutputBytes?: number;
}
/** Named immutable CA sets and an independently reviewed trust provider. */
export interface X509PluginSettings {
  readonly trustRoots: Readonly<Record<string, readonly Uint8Array[]>>;
  readonly trustProvider: MtlsTrustProvider;
  readonly policy: BoundedRuntimePolicy;
}
/** Certificate utilities and explicit trust verification; no private-key extraction. */
export interface X509Service {
  parse(pemOrDer: Uint8Array | string): X509Info;
  inspectChain(
    chain: readonly Uint8Array[],
    trust: Readonly<{
      trustRoots: readonly Uint8Array[];
      expectedHostname?: string;
      requireRevocationCheck: boolean;
    }>,
    options?: OperationOptions,
  ): Promise<CertificateValidation>;
  daysUntilExpiry(cert: X509Info, at?: string): number;
  getFingerprints(cert: X509Info): CertificateFingerprints;
}
