// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  TotpService,
  TotpServiceOptions,
  TotpStateStore,
  TotpPendingEnrollment,
  TotpFactorRecord,
  MfaSubjectContext,
  MfaEvidence,
  MfaStateStore,
  OperationOptions,
} from '../../dist/index.js';

// Compile-only consumer checks; no fake durable store or trust resolver is installed.
function contracts(
  service: TotpService,
  state: TotpStateStore,
  subject: MfaSubjectContext,
  pending: TotpPendingEnrollment,
  factor: TotpFactorRecord,
  settings: TotpServiceOptions,
  operation: OperationOptions,
): void {
  const common: MfaStateStore = state;
  const created: Promise<void> = state.putPending(pending, operation);
  const activated: Promise<boolean> = state.activatePending(
    subject,
    pending.id,
    1,
    subject.authenticatedAt,
    operation,
  );
  const accepted: Promise<boolean> = state.acceptStepIfGreater(
    subject,
    factor.id,
    factor.generation,
    2,
    operation,
  );
  const result: Promise<MfaEvidence> = service.verify(subject, '123456', operation);
  // @ts-expect-error The primary session binding cannot be omitted from pending enrollment.
  const invalidPending: TotpPendingEnrollment = {
    id: 'test',
    subject: 'test',
    issuer: 'test',
    secret: pending.secret,
    expiresAt: pending.expiresAt,
  };
  // @ts-expect-error A caller cannot mutate factor generation after reading a record.
  factor.generation = 2;
  // @ts-expect-error A two-step tolerance is outside the allowed TOTP policy.
  const invalidDrift: TotpServiceOptions = { ...settings, driftSteps: 2 };
  // @ts-expect-error The service uses exactly six digits for authenticator compatibility.
  const invalidDigits: TotpServiceOptions = { ...settings, digits: 8 };
  // @ts-expect-error Rotation/disable must include independently verified management authorization.
  service.disable(subject);
  // @ts-expect-error Step acceptance must bind the current factor generation.
  state.acceptStepIfGreater(subject, factor.id, operation);
  void [common, created, activated, accepted, result, invalidPending, invalidDrift, invalidDigits];
}
void contracts;
