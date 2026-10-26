// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { apiKeyPlugin } from '../../dist/index.js';
import type {
  ApiKeyPluginSettings,
  ApiKeyService,
  ApiKeyPolicy,
  IdentitySubject,
  SecurityStateStore,
  SecurityTransactionalStore,
} from '../../dist/index.js';

/** Compile without invoking providers; invalid public calls must remain TypeScript errors. */
export function publicContract(
  settings: ApiKeyPluginSettings,
  service: ApiKeyService,
  owner: IdentitySubject,
  grant: ApiKeyPolicy,
  partial: SecurityStateStore,
  complete: SecurityTransactionalStore,
) {
  apiKeyPlugin(settings);
  apiKeyPlugin({ ...settings, store: { ...settings.store, store: complete } });
  // @ts-expect-error Partial state cannot satisfy atomic/index/epoch requirements.
  apiKeyPlugin({ ...settings, store: { ...settings.store, store: partial } });
  // @ts-expect-error The HMAC algorithm is a closed contract.
  apiKeyPlugin({ ...settings, hmac: { ...settings.hmac, algorithm: 'SHA256' } });
  // @ts-expect-error An independent runtime authority is mandatory.
  apiKeyPlugin({ ...settings, authority: undefined });
  // @ts-expect-error Policy fields are immutable and fully typed.
  grant.scopes.push('admin');
  // @ts-expect-error A caller clock cannot override the production time source.
  service.verify('invalid', {}, { now: 0 });
  // @ts-expect-error Client addresses are explicit strings, never a request object.
  service.verify('invalid', { clientIp: {} });
  return [
    service.issue(owner, grant),
    service.verify('invalid', {}),
    service.rotate('id', owner),
    service.revoke('id', owner),
    service.list(owner),
  ];
}
