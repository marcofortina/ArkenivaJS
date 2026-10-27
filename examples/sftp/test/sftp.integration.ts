// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixtureSettings, runSftpExample } from '../dist/main.js';
test('The packed public consumer streams through OpenSSH and proves atomic publication and command completion', async () => {
  const fixture = await fixtureSettings();
  try {
    const result = await runSftpExample(fixture.settings, fixture.directory);
    assert.equal(result.text, 'ArkenivaJS transfer\n');
    assert.equal(result.uploaded.sha256, result.downloaded.sha256);
    assert.equal(result.renamed.atomicity, 'confirmed');
    assert.equal(result.command.exitCode, 0);
    assert.equal(Buffer.from(result.command.stdout).toString(), 'complete');
  } finally {
    fixture.clear();
  }
});
