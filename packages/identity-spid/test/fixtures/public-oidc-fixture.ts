// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { SpidService } from '../../dist/index.js';
import { createPublicOidcFixture } from './public-oidc-worker.js';

export type PublicOidcFixture = Awaited<ReturnType<typeof createPublicOidcFixture>>;
export type PublicOidcFixtureFiles = Parameters<typeof createPublicOidcFixture>[0];
export type PublicOidcFixtureAdapter = Parameters<typeof createPublicOidcFixture>[1];

/** Own the existing real OIDC fixture for one development scenario, including failed work. */
export async function withPublicOidcFixture<T>(
  files: PublicOidcFixtureFiles,
  work: (fixture: PublicOidcFixture, service: SpidService) => Promise<T>,
  adapter?: PublicOidcFixtureAdapter,
): Promise<T> {
  const fixture = await createPublicOidcFixture(files, adapter);
  try {
    return await work(fixture, await fixture.start());
  } finally {
    await fixture.close();
  }
}
