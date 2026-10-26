// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { parse as nativeParse } from 'csv-parse/sync';
import { createApplication, KitError } from '@arkenivajs/core';
import { createCsvService, dataCsvPlugin, CSV_CAPABILITY } from '../../dist/index.js';
import type { CsvRecord, CsvService } from '../../dist/index.js';

const settings = () => ({ defaults: {}, policy: { maxConcurrent: 2, timeoutMs: 2000 } });
const bytes = (text: string) => Buffer.from(text);
const row = (fields: readonly string[], rowIndex = 1): CsvRecord => ({ fields, rowIndex });
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
async function collect<T>(input: AsyncIterable<T>): Promise<T[]> {
  const values: T[] = [];
  for await (const value of input) values.push(value);
  return values;
}
async function text(input: AsyncIterable<Uint8Array>) {
  return Buffer.concat(await collect(input)).toString('utf8');
}
async function* split(input: Uint8Array, size = 1) {
  for (let index = 0; index < input.length; index += size)
    yield input.subarray(index, index + size);
}

test('CSV delegates quoted delimiters, CRLF/LF, escaped quotes and text-only leading zeros to the native codec', async () => {
  const csv = createCsvService(settings()),
    source = 'id,note,empty\r\n001,"hello,\r\nworld ""λ""",\r\n002,"line\nnext",value\r\n';
  const values = await collect(csv.parse(split(bytes(source)), { hasHeader: true }));
  assert.deepEqual(
    values.map((value) => value.fields),
    [
      ['001', 'hello,\r\nworld "λ"', ''],
      ['002', 'line\nnext', 'value'],
    ],
  );
  assert.deepEqual(
    values.map((value) => value.rowIndex),
    [1, 2],
  );
  assert.equal(values[0]!.columns!.id, '001');
  assert.equal(Object.getPrototypeOf(values[0]!.columns), null);
  assert.ok(Object.isFrozen(values[0]));
  assert.ok(Object.isFrozen(values[0]!.fields));
  const encoded = await text(csv.stringify(values, { hasHeader: true }));
  assert.deepEqual(nativeParse(encoded), nativeParse(source));
});
test('BOM modes work across one-byte UTF-8 fragments and preserve inner BOMs', async () => {
  const csv = createCsvService(settings()),
    source = Buffer.concat([Buffer.from([239, 187, 191]), bytes('a,b\nλ,x\n')]);
  for (const mode of ['auto', 'require'] as const)
    assert.deepEqual(
      (await collect(csv.parse(split(source), { inputBom: mode }))).map((value) => value.fields),
      [
        ['a', 'b'],
        ['λ', 'x'],
      ],
    );
  await assert.rejects(
    () => collect(csv.parse(source, { inputBom: 'forbid' })),
    code('EK_CSV_PARSE'),
  );
  await assert.rejects(
    () => collect(csv.parse(bytes('a,b\n'), { inputBom: 'require' })),
    code('EK_CSV_PARSE'),
  );
  await assert.rejects(
    () => collect(csv.parse(Buffer.from([239, 187, 191, 239, 187, 191, 97]))),
    code('EK_CSV_PARSE'),
  );
  assert.equal((await collect(csv.parse(bytes('a,\ufeffb\n'))))[0]!.fields[1], '\ufeffb');
  const encoded = Buffer.concat(
    await collect(csv.stringify([row(['λ', 'x'])], { outputBom: true })),
  );
  assert.ok(encoded.subarray(0, 3).equals(Buffer.from([239, 187, 191])));
  assert.equal(encoded.subarray(3).includes(Buffer.from([239, 187, 191])), false);
  assert.deepEqual(await collect(csv.parse(new Uint8Array())), []);
  assert.equal(await text(csv.stringify([])), '');
});
test('TSV, custom quote/escape and Unicode delimiters interoperate with native parsing', async () => {
  const csv = createCsvService(settings()),
    values = [row(['a\tb', '001', 'line\nnext', '"quote"', 'pipe|text', 'slash\\text', '😀'])];
  for (const options of [
    { delimiter: '\t' },
    { delimiter: ';', quote: '|', escape: '\\' },
    { delimiter: '🟢' },
  ]) {
    const encoded = await text(csv.stringify(values, options));
    const decoded = await collect(csv.parse(split(bytes(encoded)), options));
    assert.deepEqual(decoded[0]!.fields, values[0]!.fields);
  }
});
test('Native parsing and serialization preserve numeric header order through public record objects', async () => {
  const csv = createCsvService(settings()),
    rows = await collect(csv.parse(bytes('2,1\nsecond,first\n'), { hasHeader: true }));
  assert.deepEqual(rows[0]!.fields, ['second', 'first']);
  assert.equal(await text(csv.stringify(rows, { hasHeader: true })), '2,1\nsecond,first\n');
  assert.equal(csv.validate(rows[0]!, { columns: ['2', '1'] }).valid, true);
});
test('Header duplicates, unsafe keys, inconsistent widths and malformed quoting fail explicitly', async () => {
  const csv = createCsvService(settings());
  for (const value of ['a,a\nx,y\n', '__proto__,b\nx,y\n', 'constructor,b\nx,y\n', ''])
    await assert.rejects(
      () => collect(csv.parse(bytes(value), { hasHeader: true })),
      code('EK_CSV_SCHEMA'),
    );
  await assert.rejects(() => collect(csv.parse(bytes('a,b\nonly\n'))), code('EK_CSV_SCHEMA'));
  for (const value of ['"unterminated', 'a,"bad"suffix\n', 'a,b"quote\n'])
    await assert.rejects(() => collect(csv.parse(bytes(value))), code('EK_CSV_PARSE'));
  await assert.rejects(
    () => collect(csv.stringify([row(['value'])], { hasHeader: true })),
    code('EK_CSV_SCHEMA'),
  );
  await assert.rejects(
    () => collect(csv.stringify([row(['a']), row(['a', 'b'], 2)])),
    code('EK_CSV_SCHEMA'),
  );
});
test('Spreadsheet escaping is explicit and guards operators after whitespace and controls without changing parsing', async () => {
  const csv = createCsvService(settings()),
    fields = ['=1+1', '+1', '-1', '@name', ' \t=1', '\u0001@name', 'safe', '001', ''];
  const plain = await text(csv.stringify([row(fields)]));
  assert.deepEqual((await collect(csv.parse(bytes(plain))))[0]!.fields, fields);
  const escaped = await text(csv.stringify([row(fields)], { escapeSpreadsheetFormulas: true }));
  assert.deepEqual(
    (await collect(csv.parse(bytes(escaped))))[0]!.fields,
    fields.map((field, index) => (index < 6 ? "'" + field : field)),
  );
});
test('Row, column, raw record and aggregate byte limits reject overflow without truncating results', async () => {
  const csv = createCsvService(settings());
  for (const [source, options] of [
    ['x'.repeat(4097), { maxRecordBytes: 4096 }],
    ['a,b\n', { maxColumns: 1 }],
    ['a\nb\n', { maxRows: 1 }],
    ['"λ"\n', { maxRecordBytes: 4 }],
    ['abcdef\n', { maxTotalBytes: 6 }],
  ] as const)
    await assert.rejects(() => collect(csv.parse(bytes(source), options)), code('EK_CSV_LIMIT'));
  for (const [rows, options] of [
    [[row(['x'.repeat(4097)])], { maxRecordBytes: 4096 }],
    [[row(['a', 'b'])], { maxColumns: 1 }],
    [[row(['a']), row(['b'], 2)], { maxRows: 1 }],
    [[row(['""'])], { maxRecordBytes: 4 }],
    [[row(['abcdef'])], { maxTotalBytes: 6 }],
  ] as const)
    await assert.rejects(() => collect(csv.stringify(rows, options)), code('EK_CSV_LIMIT'));
  const constrained = createCsvService({
    defaults: {},
    policy: { maxConcurrent: 1, timeoutMs: 1000, maxInputBytes: 3, maxOutputBytes: 3 },
  });
  await assert.rejects(() => collect(constrained.parse(bytes('abcd\n'))), code('EK_CSV_LIMIT'));
  await assert.rejects(
    () => collect(constrained.stringify([row(['ab'])], { outputBom: true })),
    code('EK_CSV_LIMIT'),
  );
});
test('Malformed UTF-8, forbidden runtime coercion and source failures expose only safe error metadata', async () => {
  const csv = createCsvService(settings());
  for (const input of [Buffer.from([255]), Buffer.from([0xc0, 0xaf]), Buffer.from([0xe2, 0x82])])
    await assert.rejects(() => collect(csv.parse(split(input))), code('EK_CSV_PARSE'));
  for (const input of [null, 'a,b\n', [], { [Symbol.asyncIterator]: 1 }])
    await assert.rejects(() => collect(csv.parse(input as never)), code('EK_CSV_PARSE'));
  async function* broken() {
    yield bytes('a,b\n');
    throw new Error('private-source-value');
  }
  await assert.rejects(
    () => collect(csv.parse(broken())),
    (error) => {
      assert.ok(error instanceof KitError);
      assert.equal(error.code, 'EK_CSV_PARSE');
      assert.ok(!JSON.stringify(error.toSafeJSON()).includes('private-source-value'));
      return true;
    },
  );
  for (const input of [
    row([null as never]),
    row(['\ud800']),
    { fields: ['a'], rowIndex: 0 },
    { fields: ['a'], rowIndex: 1, extra: true },
  ])
    await assert.rejects(() => collect(csv.stringify([input as CsvRecord])), code('EK_CSV_SCHEMA'));
});
test('Configuration and operation policies reject invalid values before pulling source data', async () => {
  const csv = createCsvService(settings());
  let pulls = 0;
  async function* source() {
    pulls++;
    yield bytes('a\n');
  }
  for (const options of [
    null,
    { maxRows: 0 },
    { maxRows: null },
    { timeoutMs: 0 },
    { delimiter: '\r' },
    { delimiter: 'ab' },
    { quote: ',' },
    { escape: ',' },
    { encoding: 'latin1' },
    { inputBom: 'ignore' },
    { outputBom: 'true' },
    { signal: {} },
    { signal: { aborted: false, addEventListener() {}, removeEventListener() {} } },
    { signal: Object.create(AbortSignal.prototype) },
    { signal: null },
    { extra: true },
  ])
    await assert.rejects(
      () => collect(csv.parse(source(), options as never)),
      code('EK_CONFIG_INVALID'),
    );
  assert.equal(pulls, 0);
  for (const input of [
    null,
    {},
    { ...settings(), extra: true },
    { ...settings(), defaults: null },
    { defaults: {}, policy: { maxConcurrent: 0, timeoutMs: 1 } },
    { defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 0 } },
  ])
    assert.throws(() => createCsvService(input as never), code('EK_CONFIG_INVALID'));
});
test(
  'Abort, deadline and consumer return close native pipelines and invoke upstream cleanup',
  { timeout: 3000 },
  async () => {
    const csv = createCsvService(settings()),
      controller = new AbortController();
    let finished = false;
    async function* source() {
      try {
        for (let i = 0; i < 10000; i++) yield bytes('value\n');
      } finally {
        finished = true;
      }
    }
    const iterator = csv.parse(source(), { signal: controller.signal })[Symbol.asyncIterator]();
    await iterator.next();
    controller.abort('private-abort-reason');
    await assert.rejects(() => iterator.next(), code('EK_ABORTED'));
    await delay(0);
    assert.equal(finished, true);
    finished = false;
    const early = csv.parse(source())[Symbol.asyncIterator]();
    await early.next();
    await early.return?.();
    await delay(0);
    assert.equal(finished, true);
    let release!: () => void;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    async function* held() {
      await barrier;
      yield bytes('value\n');
    }
    try {
      await assert.rejects(() => collect(csv.parse(held(), { timeoutMs: 10 })), code('EK_TIMEOUT'));
    } finally {
      release();
      await delay(0);
    }
  },
);
test(
  'Uncooperative source cleanup retains finite admission until the actual source settles',
  { timeout: 3000 },
  async () => {
    const csv = createCsvService({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 1000 } });
    let release!: () => void,
      cleaned = false;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    async function* held() {
      try {
        yield bytes('first\nsecond\n');
        await barrier;
      } finally {
        cleaned = true;
      }
    }
    const controller = new AbortController(),
      iterator = csv.parse(held(), { signal: controller.signal })[Symbol.asyncIterator]();
    try {
      await iterator.next();
      await delay(0);
      controller.abort();
      await assert.rejects(() => iterator.next(), code('EK_ABORTED'));
      await assert.rejects(() => collect(csv.parse(bytes('other\n'))), code('EK_CSV_LIMIT'));
    } finally {
      release();
      await delay(20);
    }
    assert.equal(cleaned, true);
    assert.equal((await collect(csv.parse(bytes('other\n'))))[0]!.fields[0], 'other');
  },
);
test('Pure row validation enforces exact schema columns and never returns a value for malformed input', () => {
  const csv = createCsvService(settings()),
    input = { fields: ['001', 'value'], rowIndex: 1, columns: { id: '001', note: 'value' } };
  const accepted = csv.validate(input, { columns: ['id', 'note'] });
  assert.equal(accepted.valid, true);
  input.fields[0] = 'changed';
  if (accepted.valid) assert.equal(accepted.value.fields[0], '001');
  for (const invalid of [row(['value']), { fields: ['x', null], rowIndex: 1 }, null]) {
    const result = csv.validate(invalid as never, { columns: ['id', 'note'] });
    assert.equal(result.valid, false);
    assert.ok(!('value' in result));
  }
});
test('Managed CSV services isolate applications and reject stopped handles', async () => {
  const plugin = dataCsvPlugin(settings()),
    config = {
      service: { name: 'csv-fixture', version: '1.0.0', environment: 'test' as const },
      plugins: [plugin],
    };
  const a = await createApplication(config),
    b = await createApplication(config);
  try {
    await a.start();
    await b.start();
    const first = a.resolve<CsvService>(CSV_CAPABILITY),
      second = b.resolve<CsvService>(CSV_CAPABILITY);
    await a.stop();
    await assert.rejects(() => collect(first.parse(bytes('x\n'))), code('EK_RESOURCE_CLOSED'));
    await assert.rejects(() => collect(first.stringify([row(['x'])])), code('EK_RESOURCE_CLOSED'));
    assert.throws(() => first.validate(row(['x']), { columns: ['x'] }), code('EK_RESOURCE_CLOSED'));
    assert.equal((await collect(second.parse(bytes('x\n'))))[0]!.fields[0], 'x');
  } finally {
    await a.stop();
    await b.stop();
  }
});

test(
  'Writing honors backpressure, header-excluded row limits and upstream cleanup on return',
  { timeout: 3000 },
  async () => {
    const csv = createCsvService(settings());
    const parsed = await collect(
      csv.parse(bytes('id\n001\n002\n'), { hasHeader: true, maxRows: 2 }),
    );
    assert.equal(
      await text(csv.stringify(parsed, { hasHeader: true, maxRows: 2 })),
      'id\n001\n002\n',
    );
    let pulls = 0,
      cleaned = false;
    async function* rows() {
      try {
        for (let index = 0; index < 10000; index++) {
          pulls++;
          yield row(['x'.repeat(8192)], index + 1);
        }
      } finally {
        cleaned = true;
      }
    }
    const iterator = csv.stringify(rows())[Symbol.asyncIterator]();
    await iterator.next();
    assert.ok(pulls < 32, 'Backpressure must not consume the full input iterable');
    await iterator.return?.();
    await delay(0);
    assert.equal(cleaned, true);
  },
);

test(
  'Writing cancellation retains admission until an uncooperative row source really settles',
  { timeout: 3000 },
  async () => {
    const csv = createCsvService({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 1000 } });
    let release!: () => void,
      cleaned = false;
    const barrier = new Promise<void>((resolve) => {
      release = resolve;
    });
    async function* rows() {
      try {
        yield row(['x'.repeat(8192)]);
        await barrier;
      } finally {
        cleaned = true;
      }
    }
    const controller = new AbortController(),
      iterator = csv.stringify(rows(), { signal: controller.signal })[Symbol.asyncIterator]();
    try {
      await iterator.next();
      await delay(0);
      controller.abort();
      await assert.rejects(() => iterator.next(), code('EK_ABORTED'));
      await assert.rejects(() => collect(csv.stringify([row(['other'])])), code('EK_CSV_LIMIT'));
    } finally {
      release();
      await delay(20);
    }
    assert.equal(cleaned, true);
    assert.equal(await text(csv.stringify([row(['other'])])), 'other\n');
  },
);

test('Monotonic deadline checks reject late EOF even before a timer callback runs', async (t) => {
  let now = 0;
  t.mock.method(performance, 'now', () => now);
  const csv = createCsvService(settings());
  async function* source() {
    yield bytes('a\nb\nc\n');
    now = 1001;
  }
  await assert.rejects(() => collect(csv.parse(source(), { timeoutMs: 1000 })), code('EK_TIMEOUT'));
  now = 0;
  async function* rows() {
    yield row(['value']);
    now = 1001;
  }
  await assert.rejects(
    () => collect(csv.stringify(rows(), { timeoutMs: 1000 })),
    code('EK_TIMEOUT'),
  );
});

test(
  'Delimiter-only records are bounded at upstream field boundaries and empty chunks remain cancellable',
  { timeout: 3000 },
  async () => {
    const csv = createCsvService(settings());
    await assert.rejects(
      () => collect(csv.parse(bytes(','.repeat(100000)), { maxColumns: 4 })),
      code('EK_CSV_LIMIT'),
    );
    let closed = false;
    async function* empty() {
      try {
        while (true) yield new Uint8Array();
      } finally {
        closed = true;
      }
    }
    await assert.rejects(() => collect(csv.parse(empty(), { timeoutMs: 10 })), code('EK_TIMEOUT'));
    await delay(0);
    assert.equal(closed, true);
  },
);
