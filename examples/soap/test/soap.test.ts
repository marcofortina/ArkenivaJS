// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFixture } from '../dist/fixture.js';
import { runSoapExample } from '../dist/main.js';
test('The compiled public SOAP consumer authenticates a real TLS request and closes owned resources', async () => {
  const fixture = await createFixture();
  try {
    const result = await runSoapExample(fixture.settings, '0007', 'test');
    assert.equal(result.quantity, 42);
    assert.equal(result.status, 200);
    assert.equal(fixture.calls(), 1);
    assert.ok(fixture.requestBytes() > 0);
  } finally {
    await fixture.close();
  }
});
test('Production startup rejects the independently classified disposable secret provider', async () => {
  const fixture = await createFixture();
  try {
    await assert.rejects(runSoapExample(fixture.settings));
    assert.equal(fixture.calls(), 0);
  } finally {
    await fixture.close();
  }
});
