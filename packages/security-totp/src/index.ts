// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

export { createTotpService } from './service.js';
export type {
  TotpPendingEnrollment,
  TotpFactorRecord,
  TotpStateStore,
  TotpServiceOptions,
  TotpEnrollment,
  TotpConfirmation,
  TotpService,
  TotpComponentPolicy,
  TotpComponent,
  TotpPolicyAction,
  TotpPolicyRequest,
  TotpTrustedSubjectAuthority,
  TotpRecoveryProofInput,
  TotpRecoveryHmacProvider,
  TotpClock,
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
  MfaSealedSecret,
  MfaSecretProtector,
  MfaManagementAuthorization,
} from '@arkenivajs/core';
