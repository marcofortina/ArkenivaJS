// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import type { SpidService } from '../../dist/index.js';
import { withPublicOidcFixture } from './public-oidc-fixture.js';
import type { PublicOidcFixture, PublicOidcFixtureFiles } from './public-oidc-fixture.js';

async function failedScenario(files: PublicOidcFixtureFiles) {
  const owned: { fixture?: PublicOidcFixture; service?: SpidService } = {},
    expected = new Error('The owned fixture scenario failed');
  await assert.rejects(
    withPublicOidcFixture(files, async (fixture, service) => {
      owned.fixture = fixture;
      owned.service = service;
      const before = fixture.counters();
      assert.equal(before.serverListening, true);
      assert.equal(before.collectorListening, true);
      assert.ok((await service.metadata()).length > 0);
      assert.ok(fixture.counters().rootRequests > before.rootRequests);
      throw expected;
    }),
    (error: unknown) => error === expected,
  );
  assert.ok(owned.fixture && owned.service);
  const closed = owned.fixture.counters();
  assert.equal(closed.serverListening, false);
  assert.equal(closed.collectorListening, false);
  await assert.rejects(() => owned.service!.metadata(), { code: 'EK_RESOURCE_CLOSED' });
  const first = owned.fixture.close();
  assert.equal(owned.fixture.close(), first);
  await first;
}

process.once('message', (files: PublicOidcFixtureFiles) => {
  void failedScenario(files).then(
    () => {
      process.send?.({ ok: true, mode: 'public' });
      process.disconnect();
    },
    () => {
      process.send?.({ ok: false, message: 'Reusable OIDC fixture cleanup failed' });
      process.disconnect();
    },
  );
});
