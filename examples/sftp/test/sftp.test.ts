// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sftpPlugin, SFTP_CAPABILITY, SSH_CAPABILITY } from '@arkenivajs/sftp';
test('The public SFTP consumer imports explicit factories and distinct typed capabilities without I/O', () => {
  assert.equal(typeof sftpPlugin, 'function');
  assert.notEqual(SFTP_CAPABILITY, SSH_CAPABILITY);
});
