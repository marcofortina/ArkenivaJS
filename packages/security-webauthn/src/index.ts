// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export { createWebAuthnService } from './service.js';
export type {
  WebAuthnCredentialRecord,
  WebAuthnStateMutationResult,
  WebAuthnPolicyAction,
  WebAuthnTrustedSubjectAuthority,
  WebAuthnClock,
  WebAuthnStateStore,
  WebAuthnServiceOptions,
  WebAuthnCredentialSummary,
  PasswordlessVerifiedSubject,
  WebAuthnService,
} from './contracts.js';
export type {
  OperationOptions,
  MfaSubjectContext,
  MfaMethod,
  MfaAssurance,
  MfaEvidence,
  MfaEvidenceRecord,
  MfaEvidenceStore,
  MfaStateStore,
  MfaRateLimitStore,
  MfaManagementAuthorization,
} from '@arkenivajs/core';

/** Browser-facing serialization shapes; credential responses remain untrusted input. */
export type WebAuthnOptionsJSON = Readonly<Record<string, unknown>>;

/** An expiring ceremony reference, never an authentication session or verification proof. */
export interface WebAuthnCeremony {
  readonly ceremonyId: string;
  readonly expiresAt: string;
  readonly optionsJSON: WebAuthnOptionsJSON;
}
