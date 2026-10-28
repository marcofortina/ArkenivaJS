// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  MagicLinkService,
  MagicLinkIssue,
  MagicLinkIdentity,
  IdentitySubject,
  MagicLinkAuthority,
  TrustedSecurityAuthority,
} from '../../dist/index.js';
function boundary(service: MagicLinkService, subject: IdentitySubject, token: string) {
  const issue: Promise<MagicLinkIssue> = service.issue(subject, 'login');
  const identity: Promise<MagicLinkIdentity> = service.consume(token, {
    method: 'POST',
    purpose: 'login',
  });
  // @ts-expect-error GET requests cannot redeem a credential.
  void service.consume(token, { method: 'GET', purpose: 'login' });
  // @ts-expect-error Account identifiers alone do not satisfy the canonical issuer-bound identity contract.
  void service.issue({ id: 'user', tenantId: 'tenant' }, 'login');
  return { issue, identity };
}
void boundary;

/** The context completion preserves compatibility with the shared authorization port. */
function authorityCompatibility(shared: TrustedSecurityAuthority, magic: MagicLinkAuthority) {
  const completed: MagicLinkAuthority = shared;
  const original: TrustedSecurityAuthority = magic;
  return { completed, original };
}
void authorityCompatibility;
