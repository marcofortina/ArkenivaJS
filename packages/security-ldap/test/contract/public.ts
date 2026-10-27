// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createLdapService, ldapPlugin, LDAP_CAPABILITY } from '../../dist/index.js';
import type {
  LdapSettings,
  LdapService,
  LdapEntry,
  LdapGroup,
  LdapUser,
  OperationOptions,
} from '../../dist/index.js';
import type { Plugin } from '@arkenivajs/core';
export function contracts(settings: LdapSettings, options: OperationOptions) {
  const service: LdapService = createLdapService(settings),
    plugin: Plugin = ldapPlugin(settings),
    capability: symbol = LDAP_CAPABILITY;
  const user: Promise<LdapUser | null> = service.findUser({ username: 'alice' }, options),
    groups: Promise<readonly LdapGroup[]> = service.getGroups(
      'cn=alice,dc=fixture,dc=invalid',
      options,
    ),
    entries: AsyncIterable<LdapEntry> = service.search(
      {
        baseDn: settings.baseDn,
        filter: { template: '(uid={name})', values: { name: 'alice' } },
        attributes: ['uid'],
      },
      options,
    );
  return {
    user,
    groups,
    entries,
    plugin,
    capability,
    verified: service.verifyCredentials({ username: 'alice' }, 'public-type-example', options),
    ping: service.ping(options),
  };
}
