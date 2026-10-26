// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createIdentifiersService } from '@arkenivajs/data-identifiers';
import { createValidationService } from '@arkenivajs/data-validation';

/** Exercise public utilities without an application or external services. */
export function runUtilities() {
  const ids = createIdentifiersService({ allowVersions: [4, 7] }),
    v4 = ids.uuidV4(),
    v7 = ids.uuidV7(),
    validation = createValidationService({
      schemas: {
        order: {
          type: 'object',
          additionalProperties: false,
          required: ['id'],
          properties: { id: { type: 'integer' } },
        },
      },
      policy: { maxConcurrent: 1, timeoutMs: 1000 },
    });
  validation.assertSchema({ id: 7 }, 'order');
  const email = validation.email('User@EXAMPLE.ORG'),
    ip = validation.ip('2001:0db8:0000:0000:0000:0000:0000:0001');
  return Object.freeze({
    v4Version: ids.parseUuid(v4).version,
    v7Version: ids.parseUuid(v7).version,
    malformedRejected: !ids.isUuid('invalid'),
    canonicalPolicyEnforced: !ids.isUuid(v4.toUpperCase()),
    emailNormalized: email.valid && email.value === 'User@example.org',
    ipNormalized: ip.valid && ip.value === '2001:db8::1',
    privateUrlRejected: !validation.url('https://127.0.0.1', { schemes: ['https:'] }).valid,
    schemaAccepted: true,
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(runUtilities()));
