// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

test('The PostgreSQL example refuses an undeclared database and reports a safe missing variable error', () => {
  for (const [disposable, code] of [
    ['', 'EK_CONFIG_INVALID'],
    ['1', 'EK_CONFIG_MISSING'],
  ]) {
    const result = spawnSync(process.execPath, ['dist/main.js'], {
      encoding: 'utf8',
      env: { ...process.env, DATABASE_URL: '', ARKENIVA_POSTGRES_DISPOSABLE: disposable },
    });
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal((JSON.parse(result.stderr) as { code: string }).code, code);
  }
});
