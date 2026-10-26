// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Identity } from '@arkenivajs/core';
import { sessionsPlugin } from '../../dist/index.js';
import type {
  SessionsPluginSettings,
  SessionService,
  SessionPolicy,
  IdentitySubject,
  SecurityStateStore,
  SecurityTransactionalStore,
  TrustedSecurityAuthority,
} from '../../dist/index.js';

/** Compile public calls and negative fixtures without executing provider operations. */
export function publicContract(
  settings: SessionsPluginSettings,
  service: SessionService,
  identity: Identity,
  owner: IdentitySubject,
  policy: SessionPolicy,
  partial: SecurityStateStore,
  complete: SecurityTransactionalStore,
  authorizationOnly: TrustedSecurityAuthority,
) {
  sessionsPlugin(settings);
  sessionsPlugin({ ...settings, store: { ...settings.store, store: complete } });
  // @ts-expect-error A partial store cannot provide atomic renewal or global revocation.
  sessionsPlugin({ ...settings, store: { ...settings.store, store: partial } });
  // @ts-expect-error Independent canonical authentication metadata is mandatory.
  sessionsPlugin({ ...settings, authority: authorizationOnly });
  // @ts-expect-error Callers cannot override trusted production time.
  service.validate('invalid', { now: 0 });
  // @ts-expect-error Cookie SameSite policy is a closed union.
  service.create(identity, { ...policy, cookieSameSite: 'unsafe' });
  // @ts-expect-error Policy fields are immutable.
  policy.absoluteTtlMs = 1;
  return [
    service.create(identity, policy),
    service.validate('invalid'),
    service.renew('invalid'),
    service.revoke('id'),
    service.revokeAll(owner),
  ];
}
