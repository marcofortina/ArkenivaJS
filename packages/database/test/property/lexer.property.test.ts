// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { KitError } from '@arkenivajs/core';
import { compileSql } from '@arkenivajs/database';
import type { SqlDialect } from '@arkenivajs/database';

const dialects: readonly SqlDialect[] = ['postgres', 'mysql', 'mariadb', 'oracle'];
const word = fc
  .array(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz_0123456789'), { maxLength: 32 })
  .map((characters) => 'p' + characters.join(''));
const payload = fc
  .array(fc.constantFrom(...' abcXYZ_012:-/*$#!\'"`\\\n\r😀é'), { maxLength: 120 })
  .map((characters) => characters.join(''));

test('EK-DB-001 property: varied quote and comment transitions hide every inner bind', () => {
  fc.assert(
    fc.property(payload, word, (content, name) => {
      for (const dialect of dialects) {
        // Neutralize only the delimiter; keep hostile colons and state-transition characters.
        const escaped = content.replaceAll('\\', '\\\\').replaceAll("'", "''");
        const literal = `'${escaped} :not_bound'`;
        const line = '-- ' + content.replace(/[\r\n]/g, ' ') + ' :not_bound\n';
        const block =
          '/* ' + content.replaceAll('/*', '/ *').replaceAll('*/', '* /') + ' :not_bound */';
        const text = `SELECT ${literal}, ${block}\n${line}:${name}, :${name}`;
        const result = compileSql({ text, bindings: { [name]: 7 } }, dialect);
        assert.deepEqual(result.names, [name, name]);
        assert.deepEqual(
          Array.isArray(result.parameters) ? result.parameters : Object.values(result.parameters),
          dialect === 'mysql' || dialect === 'mariadb' ? [7, 7] : [7],
        );
      }
    }),
    { seed: 24102026, numRuns: 1000 },
  );
});

test('EK-DB-001 fuzz: arbitrary UTF-16 input either compiles or returns a typed validation error', () => {
  const arbitraryText = fc
    .array(fc.integer({ min: 0, max: 65535 }), { maxLength: 500 })
    .map((units) => String.fromCharCode(...units));
  fc.assert(
    fc.property(arbitraryText, (text) => {
      for (const dialect of dialects) {
        try {
          const result = compileSql({ text }, dialect);
          assert.equal(typeof result.text, 'string');
          assert.ok(Object.isFrozen(result));
          assert.equal(result.names.length, 0);
        } catch (error) {
          assert.ok(error instanceof KitError);
          assert.equal(error.code, 'EK_CONFIG_INVALID');
        }
      }
    }),
    { seed: 24102029, numRuns: 2000 },
  );
});

test('EK-DB-001 property: arbitrary binding payloads never alter compiled SQL or fingerprints', () => {
  fc.assert(
    fc.property(word, payload, payload, (name, left, right) => {
      for (const dialect of dialects) {
        const text = `SELECT :${name}, :${name}`;
        const a = compileSql({ text, bindings: { [name]: left } }, dialect);
        const b = compileSql({ text, bindings: { [name]: right } }, dialect);
        assert.equal(a.text, b.text);
        assert.equal(a.fingerprint, b.fingerprint);
        assert.deepEqual(a.names, b.names);
      }
    }),
    { seed: 24102027, numRuns: 1000 },
  );
});

test('EK-DB-001 property: dollar and alternative quoted bodies cannot introduce placeholders', () => {
  fc.assert(
    fc.property(payload, word, (content, name) => {
      const pg = '$body$' + content.replaceAll('$body$', '$body $') + ' :hidden$body$';
      assert.deepEqual(
        compileSql({ text: `SELECT ${pg}, :${name}`, bindings: { [name]: 1 } }, 'postgres').names,
        [name],
      );
      const oracle = "q'[" + content.replaceAll("]'", "] '") + " :hidden]'";
      assert.deepEqual(
        compileSql({ text: `SELECT ${oracle}, :${name}`, bindings: { [name]: 1 } }, 'oracle').names,
        [name],
      );
    }),
    { seed: 24102028, numRuns: 1000 },
  );
});
