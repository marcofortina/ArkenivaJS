// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { networkInterfaces } from 'node:os';
import { runXsdExample } from '../dist/main.js';
test('The compiled public XSD consumer validates through the real vetted engine and registered offline imports', async () => {
  assert.equal(process.env.ARKENIVA_XML_NS_ACTIVE, '1');
  assert.notEqual(process.getuid?.(), 0);
  assert.ok(Object.keys(networkInterfaces()).every((name) => name === 'lo'));
  const result = await runXsdExample();
  assert.equal(result.valid.valid, true);
  assert.deepEqual(result.valid.messages, []);
  assert.equal(result.invalid.valid, false);
  assert.equal(result.invalid.messages[0]?.code, 'EK_XML_SCHEMA');
});
