import test from 'node:test';
import assert from 'node:assert/strict';
import { KitError } from '@arkenivajs/core';
import type { SqlStatement, SqlValue } from '@arkenivajs/core';
import { compileSql, SQL_LIMITS } from '@arkenivajs/database';
import type { SqlDialect } from '@arkenivajs/database';
import { captureSqlStatement } from '@arkenivajs/database/support';

const dialects: readonly SqlDialect[] = ['postgres', 'mysql', 'mariadb', 'oracle'];
const invalid = (error: unknown): boolean =>
  error instanceof KitError && error.code === 'EK_CONFIG_INVALID';

test('EK-DB-001 queued statement capture preserves values before the actual session mode is known', () => {
  const date = new Date('2026-10-24T00:00:00Z');
  const binary = new Uint8Array([1, 2]);
  const input = { text: "SELECT 'escape\\' :hidden', :date, :binary", bindings: { date, binary } };
  const captured = captureSqlStatement(input);
  input.text = 'changed';
  date.setTime(0);
  binary[0] = 9;
  assert.ok(Object.isFrozen(captured));
  assert.ok(Object.isFrozen(captured.bindings));
  assert.equal(Object.getPrototypeOf(captured.bindings), null);
  assert.equal((captured.bindings!.date as Date).toISOString(), '2026-10-24T00:00:00.000Z');
  assert.deepEqual(captured.bindings!.binary, new Uint8Array([1, 2]));
  assert.deepEqual(compileSql(captured, 'postgres', { standardConformingStrings: false }).names, [
    'date',
    'binary',
  ]);
  assert.throws(() => captureSqlStatement({ text: '' }), invalid);
  assert.throws(
    () => captureSqlStatement({ text: 'SELECT :a', bindings: { a: {} as never } }),
    invalid,
  );
});

test('EK-DB-001 compiles exact named binds with dialect-specific repeated parameters', () => {
  for (const dialect of dialects) {
    const input = Object.freeze({
      text: 'SELECT :b, :a, :b, :_zero',
      bindings: Object.freeze({ a: 'data', b: 5n, _zero: 0 }),
    });
    const compiled = compileSql(input, dialect);
    assert.equal(compiled.dialect, dialect);
    assert.deepEqual(compiled.names, ['b', 'a', 'b', '_zero']);
    assert.equal(
      compiled.text,
      dialect === 'postgres'
        ? 'SELECT $1, $2, $1, $3'
        : dialect === 'oracle'
          ? input.text
          : 'SELECT ?, ?, ?, ?',
    );
    if (dialect === 'oracle') {
      assert.equal(Object.getPrototypeOf(compiled.parameters), null);
      assert.deepEqual({ ...compiled.parameters }, { b: 5n, a: 'data', _zero: 0 });
    } else
      assert.deepEqual(
        compiled.parameters,
        dialect === 'postgres' ? [5n, 'data', 0] : [5n, 'data', 5n, 0],
      );
    assert.ok(Object.isFrozen(compiled));
    assert.ok(Object.isFrozen(compiled.names));
    assert.ok(Object.isFrozen(compiled.parameters));
    assert.throws(() => (compiled.names as string[]).push('extra'), TypeError);
  }
});

test('EK-DB-001 ignores ordinary quoted tokens, doubled delimiters and SQL comments', () => {
  const text = `SELECT ':fake'' :still_fake', "column"" :hidden", :real
/* :hidden_again */ -- :line_hidden
:real`;
  for (const dialect of dialects) {
    const result = compileSql({ text, bindings: { real: true } }, dialect);
    assert.deepEqual(result.names, ['real', 'real']);
    assert.ok(result.text.includes("':fake'' :still_fake'"));
    assert.ok(result.text.includes('/* :hidden_again */ -- :line_hidden'));
    assert.deepEqual(compileSql({ text: 'SELECT 1 -- :no_bind' }, dialect).names, []);
    for (const quote of ["'", '"'])
      assert.throws(() => compileSql({ text: `SELECT ${quote}:hidden` }, dialect), invalid);
    assert.throws(() => compileSql({ text: 'SELECT /* never closed :x' }, dialect), invalid);
  }
});

test('EK-DB-001 PostgreSQL handles casts, nested comments, Unicode dollar tags and escape continuations', () => {
  const text = `SELECT :id::integer, 1::integer,
$$' :fake /* body */$$, $body$:other $inner$ :ignored $inner$ $body$,
$é_$:not_a_bind$é_$, E'quote\\' :hidden',
'ordinary backslash\\', :id /* outer :fake /* inner */ :also_hidden */`;
  const result = compileSql({ text, bindings: { id: 3 } }, 'postgres');
  assert.deepEqual(result.names, ['id', 'id']);
  assert.equal(result.text, text.replaceAll(':id', '$1'));
  const continued = "SELECT E'first' -- comment\r\n 'escaped\\' :hidden', :value";
  assert.deepEqual(compileSql({ text: continued, bindings: { value: 1 } }, 'postgres').names, [
    'value',
  ]);
  const legacy = "SELECT 'escaped\\' :hidden', :value";
  assert.deepEqual(
    compileSql({ text: legacy, bindings: { value: 1 } }, 'postgres', {
      standardConformingStrings: false,
    }).names,
    ['value'],
  );
  assert.throws(() => compileSql({ text: 'SELECT $tag$:never_closed' }, 'postgres'), invalid);
  assert.throws(
    () => compileSql({ text: 'SELECT $1, :x', bindings: { x: 1 } }, 'postgres'),
    invalid,
  );
  assert.deepEqual(
    compileSql({ text: 'SELECT identifier$tag$, :x', bindings: { x: null } }, 'postgres').names,
    ['x'],
  );
  assert.deepEqual(
    compileSql({ text: 'SELECT data ? :key', bindings: { key: 'name' } }, 'postgres').parameters,
    ['name'],
  );
  for (const prefix of ['B', 'X', 'U&'])
    assert.deepEqual(
      compileSql({ text: `SELECT ${prefix}'body\\', :x`, bindings: { x: 0 } }, 'postgres', {
        standardConformingStrings: false,
      }).names,
      ['x'],
    );
  assert.throws(
    () => compileSql({ text: 'SELECT /* outer /* nested */ still open' }, 'postgres'),
    invalid,
  );
});

test('EK-DB-001 MySQL and MariaDB honor comment boundaries, identifiers and session string modes', () => {
  for (const dialect of ['mysql', 'mariadb'] as const) {
    const text =
      'SELECT `col``:hidden`, \'escaped\\\' :hidden\', "double\\" :hidden", :x # :hidden\n --\t:hidden\n :x';
    assert.deepEqual(compileSql({ text, bindings: { x: 2 } }, dialect).names, ['x', 'x']);
    assert.deepEqual(
      compileSql({ text: 'SELECT 1--:x', bindings: { x: 2 } }, dialect).parameters,
      [2],
    );
    assert.deepEqual(compileSql({ text: 'SELECT 1--' }, dialect).names, []);
    assert.deepEqual(
      compileSql({ text: "SELECT 'backslash\\', :x", bindings: { x: 3 } }, dialect, {
        noBackslashEscapes: true,
      }).parameters,
      [3],
    );
    assert.deepEqual(
      compileSql({ text: 'SELECT "column\\", :x', bindings: { x: 3 } }, dialect, {
        ansiQuotes: true,
      }).parameters,
      [3],
    );
    assert.deepEqual(
      compileSql({ text: 'SELECT `column\\`, :x', bindings: { x: 3 } }, dialect).parameters,
      [3],
    );
    assert.throws(() => compileSql({ text: 'SELECT `:unclosed' }, dialect), invalid);
    assert.throws(
      () => compileSql({ text: 'SELECT /*!80000 :x */', bindings: { x: 1 } }, dialect),
      invalid,
    );
    assert.throws(() => compileSql({ text: 'SELECT ?' }, dialect), invalid);
    assert.deepEqual(
      compileSql({ text: 'SELECT /* outer /* not nested */ :x', bindings: { x: 1 } }, dialect)
        .names,
      ['x'],
    );
    assert.deepEqual(compileSql({ text: 'SELECT /*+ :hint */ 1' }, dialect).names, []);
  }
  assert.throws(
    () => compileSql({ text: 'SELECT /*M! :x */', bindings: { x: 1 } }, 'mariadb'),
    invalid,
  );
  assert.deepEqual(compileSql({ text: 'SELECT /*M! :ignored */ 1' }, 'mysql').names, []);
});

test('EK-DB-001 Oracle alternative quotes support paired, repeated and multibyte delimiters', () => {
  for (const [open, close] of [
    ['[', ']'],
    ['{', '}'],
    ['<', '>'],
    ['(', ')'],
    ['!', '!'],
    ["'", "'"],
    ['😀', '😀'],
  ]) {
    for (const prefix of ['q', 'Q', 'nq', 'NQ']) {
      const text = `SELECT ${prefix}'${open}quoted ' :hidden ${close}', :real FROM dual`;
      const result = compileSql({ text, bindings: { real: false } }, 'oracle');
      assert.equal(result.text, text);
      assert.deepEqual({ ...result.parameters }, { real: false });
    }
  }
  for (const text of ["SELECT q'", "SELECT q' :bad '", "SELECT q'[never_closed'", 'SELECT :1'])
    assert.throws(() => compileSql({ text }, 'oracle'), invalid);
  assert.deepEqual(
    compileSql(
      { text: "BEGIN result := ':ignored'; SELECT :x; END;", bindings: { x: 0 } },
      'oracle',
    ).names,
    ['x'],
  );
  assert.deepEqual(
    compileSql({ text: "SELECT identifierq':quoted', :x", bindings: { x: 0 } }, 'oracle').names,
    ['x'],
  );
});

test('EK-DB-001 captures Date, binary, scalar and large bigint values without interpolation or precision loss', () => {
  const date = new Date('2026-10-24T12:00:00Z');
  const bytes = new Uint8Array([0, 255]);
  const hostile = "'; DROP TABLE records; -- :fake 😀";
  const values = {
    date,
    bytes,
    hostile,
    bigint: 90071992547409930000000000001n,
    nil: null,
    zero: 0,
  };
  const statement = {
    text: 'SELECT :date, :bytes, :hostile, :bigint, :nil, :zero',
    bindings: values,
  };
  const compiled = compileSql(statement, 'postgres');
  const captured = compiled.parameters as readonly SqlValue[];
  date.setTime(0);
  bytes[0] = 42;
  values.hostile = 'changed';
  assert.equal((captured[0] as Date).toISOString(), '2026-10-24T12:00:00.000Z');
  assert.deepEqual(captured[1], new Uint8Array([0, 255]));
  assert.equal(captured[2], hostile);
  assert.equal(captured[3], 90071992547409930000000000001n);
  assert.equal(captured[4], null);
  assert.equal(captured[5], 0);
  assert.ok(!compiled.text.includes(hostile));
  assert.match(compiled.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(compiled.fingerprint, compileSql(statement, 'postgres').fingerprint);
  assert.notEqual(compiled.fingerprint, compileSql(statement, 'mysql').fingerprint);
});

test('EK-DB-001 uses exact own keys including prototype-like legal identifiers without prototype pollution', () => {
  for (const dialect of dialects) {
    const bindings = Object.assign(Object.create(null) as Record<string, SqlValue>, {
      constructor: 1,
      prototype: 2,
    });
    bindings.__proto__ = 3;
    const result = compileSql(
      { text: 'SELECT :constructor, :prototype, :__proto__', bindings },
      dialect,
    );
    assert.deepEqual(result.names, ['constructor', 'prototype', '__proto__']);
    assert.equal(Object.getPrototypeOf({}), Object.prototype);
    if (dialect === 'oracle') {
      assert.equal(Object.getPrototypeOf(result.parameters), null);
      assert.equal((result.parameters as Record<string, SqlValue>).__proto__, 3);
    }
  }
});

test('EK-DB-001 rejects invalid, missing, extra and accessor input without printing sensitive SQL or bindings', () => {
  let invoked = false;
  const accessor = Object.defineProperty({}, 'x', {
    enumerable: true,
    get() {
      invoked = true;
      return 1;
    },
  });
  const cases: unknown[] = [
    null,
    'SELECT 1',
    {},
    { text: '' },
    { text: '  ' },
    { text: 'SELECT\0 1' },
    { text: 'SELECT :missing' },
    { text: 'SELECT :x', bindings: { x: 1, extra: 2 } },
    { text: 'SELECT :x', bindings: { X: 1 } },
    { text: 'SELECT :xé', bindings: { x: 1 } },
    { text: 'SELECT :x$', bindings: { x: 1 } },
    { text: 'SELECT :é' },
    { text: 'SELECT 1', bindings: [] },
    { text: 'SELECT 1', bindings: { 'bad-key': 1 } },
    { text: 'SELECT 1', bindings: { 'x\n': 1 } },
    { text: 'SELECT :x', bindings: accessor },
    Object.defineProperty({}, 'text', {
      get() {
        invoked = true;
        return 'SELECT 1';
      },
    }),
    { text: 'SELECT 1', bindings: { [Symbol('x')]: 1 } },
    { text: 'SELECT 1', bindings: Object.create({ inherited: 1 }) },
    ...[
      undefined,
      NaN,
      Infinity,
      Number.MAX_SAFE_INTEGER + 1,
      {},
      [],
      () => 1,
      Symbol(),
      new Date(NaN),
    ].map((x) => ({ text: 'SELECT :x', bindings: { x } })),
  ];
  for (const dialect of dialects)
    for (const input of cases)
      assert.throws(() => compileSql(input as SqlStatement, dialect), invalid);
  assert.equal(invoked, false);
  assert.throws(
    () => compileSql({ text: 'SELECT :secret', bindings: { other: 'private-value' } }, 'postgres'),
    (error: unknown) => {
      assert.ok(invalid(error));
      assert.ok(!JSON.stringify(error).includes('secret'));
      assert.ok(!JSON.stringify(error).includes('private-value'));
      return true;
    },
  );
});

test('EK-DB-001 enforces lexical option and resource bounds before acquisition', () => {
  assert.throws(() => compileSql({ text: 'SELECT 1' }, 'unknown' as SqlDialect), invalid);
  for (const options of [null, [], { ansiQuotes: 1 }, { unknown: true }, { ansiQuotes: true }])
    assert.throws(() => compileSql({ text: 'SELECT 1' }, 'postgres', options as never), invalid);
  assert.throws(
    () => compileSql({ text: 'SELECT 1' }, 'mysql', { standardConformingStrings: true }),
    invalid,
  );
  assert.throws(
    () => compileSql({ text: 'SELECT 1' }, 'oracle', { [Symbol()]: true } as never),
    invalid,
  );
  assert.throws(
    () => compileSql({ text: 'x'.repeat(SQL_LIMITS.statementBytes + 1) }, 'postgres'),
    invalid,
  );
  assert.throws(
    () =>
      compileSql(
        { text: 'SELECT :x', bindings: { x: 'x'.repeat(SQL_LIMITS.bindingBytes) } },
        'postgres',
      ),
    invalid,
  );
  const repeated = {
    text: 'SELECT :x, :x',
    bindings: { x: 'a'.repeat(SQL_LIMITS.bindingBytes / 2) },
  };
  assert.throws(() => compileSql(repeated, 'mysql'), invalid);
  assert.equal((compileSql(repeated, 'postgres').parameters as readonly SqlValue[]).length, 1);
  assert.throws(
    () =>
      compileSql(
        { text: 'SELECT :x', bindings: { x: new Uint8Array(SQL_LIMITS.bindingBytes + 1) } },
        'postgres',
      ),
    invalid,
  );
  const tooMany = Object.fromEntries(
    Array.from({ length: SQL_LIMITS.parameterCount + 1 }, (_, i) => [`p${i}`, 1]),
  );
  assert.throws(() => compileSql({ text: 'SELECT 1', bindings: tooMany }, 'postgres'), invalid);
  assert.throws(
    () =>
      compileSql(
        {
          text:
            'SELECT ' +
            Array(SQL_LIMITS.parameterCount + 1)
              .fill(':x')
              .join(','),
          bindings: { x: 0 },
        },
        'mysql',
      ),
    invalid,
  );
  assert.equal(compileSql({ text: 'SELECT 1' }, 'postgres').text, 'SELECT 1');
});
