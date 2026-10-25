// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { KitError } from '@arkenivajs/core';
import { createAuthService } from '@arkenivajs/security';

test('EK-AUTH-002 arbitrary object graphs and casts cannot establish tenant provenance', async () => {
  const auth = await createAuthService({
    issuer: 'https://issuer.example.invalid',
    audience: 'api://property',
    jwksUrl: 'https://issuer.example.invalid/keys',
  });
  try {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        assert.equal(auth.isVerifiedTenant(value), false);
        assert.throws(
          () => auth.tenantFrom(value as never),
          (error) => error instanceof KitError && error.code === 'EK_TENANT_UNVERIFIED',
        );
      }),
      { seed: 2602, numRuns: 500 },
    );
  } finally {
    await auth.close();
  }
});
