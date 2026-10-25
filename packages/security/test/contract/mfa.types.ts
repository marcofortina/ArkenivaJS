// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  MfaSubjectContext,
  MfaStateStore,
  MfaChallengeRecord,
  MfaEvidence,
  MfaEvidenceRecord,
  MfaEvidenceStore,
  MfaRateLimitStore,
  MfaSealedSecret,
  MfaSecretProtector,
  MfaManagementAuthorization,
  OperationOptions,
} from '@arkenivajs/core';
import type {
  MfaStateStore as SecurityStateStore,
  MfaEvidenceStore as SecurityEvidenceStore,
  MfaRateLimitStore as SecurityRateLimitStore,
  MfaSecretProtector as SecuritySecretProtector,
} from '../../src/index.js';

// This compile-only fixture checks public consumer types without simulating durable storage.
function publicContracts(
  subject: MfaSubjectContext,
  challenge: MfaChallengeRecord,
  evidence: MfaEvidenceRecord,
  state: SecurityStateStore,
  handoff: SecurityEvidenceStore,
  limiter: SecurityRateLimitStore,
  protector: SecuritySecretProtector,
  authorization: MfaManagementAuthorization,
  options: OperationOptions,
): void {
  const stores: [MfaStateStore, MfaEvidenceStore, MfaRateLimitStore, MfaSecretProtector] = [
    state,
    handoff,
    limiter,
    protector,
  ];
  const created: Promise<void> = state.createChallenge(challenge, options);
  const claimed: Promise<MfaChallengeRecord | null> = state.claimChallenge(
    {
      id: challenge.id,
      purpose: challenge.purpose,
      issuer: subject.issuer,
      subject: subject.subject,
      primarySessionId: subject.primarySessionId,
      now: subject.authenticatedAt,
    },
    options,
  );
  const recorded: Promise<void> = handoff.recordOnce(evidence, options);
  const consumed: Promise<MfaEvidenceRecord | null> = handoff.consume(
    {
      evidenceId: evidence.evidenceId,
      issuer: subject.issuer,
      subject: subject.subject,
      primarySessionId: subject.primarySessionId,
      now: subject.authenticatedAt,
    },
    options,
  );
  const decision: Promise<{ allowed: boolean; retryAfterMs?: number }> = limiter.checkAndRecord(
    { scopeKey: 'synthetic-bucket', operation: 'verify', maxAttempts: 5, windowMs: 1000, nowMs: 0 },
    options,
  );
  const sealed: Promise<MfaSealedSecret> = protector.seal(
    new Uint8Array(),
    { issuer: subject.issuer, subject: subject.subject },
    options,
  );
  const baseEvidence: MfaEvidence = evidence;
  // @ts-expect-error Evidence without the original issuer and session is insufficient for durable handoff.
  handoff.recordOnce(baseEvidence, options);
  // @ts-expect-error Consumption cannot omit the authenticated primary session binding.
  handoff.consume({
    evidenceId: evidence.evidenceId,
    issuer: subject.issuer,
    subject: subject.subject,
    now: evidence.verifiedAt,
  });
  // @ts-expect-error Challenge consumption must select one exact factor ceremony purpose.
  state.claimChallenge({ id: challenge.id, issuer: subject.issuer, now: subject.authenticatedAt });
  // @ts-expect-error Issuer identity cannot be changed after trusted subject resolution.
  subject.issuer = 'https://untrusted.example.test';
  // @ts-expect-error Optional ownership fields are absent rather than explicitly undefined.
  const invalidSubject: MfaSubjectContext = { ...subject, tenant: undefined };
  // @ts-expect-error A management action is a closed operation class rather than an arbitrary string.
  const invalidAuthorization: MfaManagementAuthorization = { ...authorization, action: 'bypass' };
  void [
    stores,
    created,
    claimed,
    recorded,
    consumed,
    decision,
    sealed,
    invalidSubject,
    invalidAuthorization,
  ];
}
void publicContracts;
