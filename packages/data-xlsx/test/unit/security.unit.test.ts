// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir, stat, rm, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import ExcelJS from 'exceljs';
import { unzipSync, zipSync, strToU8, strFromU8 } from 'fflate';
import { KitError } from '@arkenivajs/core';
import type { XlsxCell, XlsxOptions, DataXlsxPluginSettings } from '../../dist/index.js';
import { managedService } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';
import { cell, style, formula, row } from '../../dist/cells.js';
import { options } from '../../dist/settings.js';
import { operation } from '../../dist/runtime.js';

const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function fixture(config: Partial<DataXlsxPluginSettings> = {}) {
  const controller = new AbortController(),
    managed = managedService(
      capture({ defaults: {}, policy: { maxConcurrent: 2, timeoutMs: 10000 }, ...config }),
      controller.signal,
      () => true,
    );
  return { ...managed, controller };
}
async function native(values: unknown[][] = [[1]], date1904 = false): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  workbook.properties.date1904 = date1904;
  workbook.addWorksheet('Data').addRows(values);
  return Buffer.from(await workbook.xlsx.writeBuffer());
}
function edit(input: Buffer, part: string, change: (text: string) => string): Buffer {
  const archive = unzipSync(input);
  assert.ok(archive[part]);
  archive[part] = strToU8(change(strFromU8(archive[part]!)));
  return Buffer.from(zipSync(archive));
}
async function collect<T>(source: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const value of source) result.push(value);
  return result;
}
const value = (cell: XlsxCell) =>
  cell && typeof cell === 'object' && !(cell instanceof Date) && 'value' in cell
    ? cell.value
    : cell;
test('XLSX cancellation owns native hooks independently of later caller mutation', async () => {
  const f = fixture(),
    controller = new AbortController();
  let release!: (value: IteratorResult<Uint8Array>) => void,
    effects = 0;
  const pending = f.service.open(
    {
      [Symbol.asyncIterator]() {
        return {
          next: () =>
            new Promise<IteratorResult<Uint8Array>>((resolve) => {
              release = resolve;
            }),
        };
      },
    },
    { signal: controller.signal },
  );
  try {
    await delay(0);
    Object.defineProperty(controller.signal, 'removeEventListener', {
      value() {
        effects++;
      },
    });
    release({ done: true, value: undefined });
    await assert.rejects(pending, code('EK_XLSX_FORMAT'));
    assert.equal(effects, 0);
    const writer = f.service.create();
    await writer.close();
  } finally {
    release?.({ done: true, value: undefined });
    await f.close();
  }
});
test('XLSX operation signals reject proxies and bounded prototype overflow without executing traps', () => {
  let effects = 0;
  const signal = new AbortController().signal;
  const proxy = new Proxy(signal, {
    getPrototypeOf(target) {
      effects++;
      return Reflect.getPrototypeOf(target);
    },
  });
  assert.throws(() => operation({ signal: proxy }, 1000), code('EK_XLSX_FORMAT'));
  assert.equal(effects, 0);
  const deep = new AbortController().signal;
  let prototype: object = AbortSignal.prototype;
  for (let index = 0; index < 65; index++) prototype = Object.create(prototype) as object;
  Object.setPrototypeOf(deep, prototype);
  assert.throws(() => operation({ signal: deep }, 1000), code('EK_XLSX_FORMAT'));
});
test('Real XLSX 1900 and 1904 date epochs preserve UTC milliseconds and ordinary numeric styles', async () => {
  const f = fixture();
  try {
    for (const epoch of [false, true]) {
      const expected = new Date('2026-10-27T01:02:03Z'),
        bytes = await native([[expected, 123.45]], epoch),
        reader = await f.service.open(bytes);
      const rows = await collect(reader.rows('Data'));
      assert.equal((value(rows[0]!.cells[0]!) as Date).toISOString(), expected.toISOString());
      assert.equal(value(rows[0]!.cells[1]!), 123.45);
      await reader.close();
    }
  } finally {
    await f.close();
  }
});
test('Formula policies preserve every supported cached type as data and never interpret untrusted string prefixes', async () => {
  const f = fixture();
  try {
    const bytes = await native([
      [
        { formula: '1+1', result: 2 },
        { formula: 'TRUE()', result: true },
        { formula: 'FALSE()', result: false },
        { formula: '"a&amp;b"', result: 'a&amp;b' },
        { formula: '1' },
        '=SUM(1,2)',
      ],
    ]);
    await assert.rejects(f.service.open(bytes), code('EK_XLSX_UNSUPPORTED'));
    const reader = await f.service.open(bytes, { formulaPolicy: 'preserve' }),
      rows = await collect(reader.rows('Data'));
    assert.deepEqual(rows[0]!.cells.map(value), [
      { formula: '1+1', cachedValue: 2 },
      { formula: 'TRUE()', cachedValue: true },
      { formula: 'FALSE()', cachedValue: false },
      { formula: '"a&amp;b"', cachedValue: 'a&amp;b' },
      { formula: '1', cachedValue: null },
      '=SUM(1,2)',
    ]);
    await reader.close();
    const stripped = await f.service.open(bytes, { formulaPolicy: 'strip' });
    assert.deepEqual((await collect(stripped.rows('Data')))[0]!.cells.map(value), [
      2,
      true,
      false,
      'a&amp;b',
      null,
      '=SUM(1,2)',
    ]);
    await stripped.close();
  } finally {
    await f.close();
  }
});
test('Inline XML entities and cached strings retain their literal value exactly once', async () => {
  const f = fixture();
  try {
    const bytes = edit(await native(), 'xl/worksheets/sheet1.xml', (xml) =>
      xml.replace(
        /<c\b[^>]*>.*?<\/c>/s,
        '<c r="A1" t="inlineStr"><is><t>a&amp;amp;b &lt;λ&gt;</t></is></c>',
      ),
    );
    const reader = await f.service.open(bytes);
    assert.equal(value((await collect(reader.rows('Data')))[0]!.cells[0]!), 'a&amp;b <λ>');
    await reader.close();
  } finally {
    await f.close();
  }
});
test('Corrupt, encrypted, traversal, macro, external-link and DTD payloads are rejected by isolated parsers', async () => {
  const f = fixture(),
    bytes = await native(),
    archive = unzipSync(bytes);
  const unsupported: Buffer[] = [
    Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
    edit(bytes, 'xl/workbook.xml', (text) =>
      text.replace(
        '<workbook ',
        '<!DOCTYPE workbook [<!ENTITY x SYSTEM "file:///etc/passwd">]><workbook ',
      ),
    ),
    edit(bytes, 'xl/_rels/workbook.xml.rels', (text) =>
      text.replace(
        '</Relationships>',
        '<Relationship Id="external" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="http://127.0.0.1/" TargetMode="External"/></Relationships>',
      ),
    ),
    Buffer.from(zipSync({ ...archive, 'xl/vbaProject.bin': new Uint8Array([1]) })),
  ];
  try {
    for (const input of unsupported)
      await assert.rejects(f.service.open(input), code('EK_XLSX_UNSUPPORTED'));
    for (const input of [
      Buffer.from('invalid workbook'),
      bytes.subarray(0, bytes.length - 15),
      Buffer.from(zipSync({ ...archive, '../escape.xml': strToU8('<x/>') })),
    ])
      await assert.rejects(f.service.open(input), code('EK_XLSX_FORMAT'));
  } finally {
    await f.close();
  }
});
test('Measured expansion, actual style records, duplicate coordinates and malformed booleans cannot bypass quotas', async () => {
  const f = fixture(),
    bytes = await native();
  try {
    const samples: Array<[Buffer, XlsxOptions, string]> = [
      [bytes, { maxUncompressedBytes: bytes.length + 200 }, 'EK_XLSX_LIMIT'],
      [
        edit(bytes, 'xl/styles.xml', (xml) =>
          xml.replace(
            /<fonts\b[^>]*>.*?<\/fonts>/s,
            '<fonts count="1">' + '<font><name val="Arial"/></font>'.repeat(257) + '</fonts>',
          ),
        ),
        {},
        'EK_XLSX_LIMIT',
      ],
      [
        edit(bytes, 'xl/worksheets/sheet1.xml', (xml) =>
          xml.replace('</row>', '<c r="A1"><v>2</v></c></row>'),
        ),
        {},
        'EK_XLSX_LIMIT',
      ],
      [
        edit(bytes, 'xl/worksheets/sheet1.xml', (xml) =>
          xml.replace(/<c\b[^>]*>.*?<\/c>/s, '<c r="A1" t="b"><v>false</v></c>'),
        ),
        {},
        'EK_XLSX_FORMAT',
      ],
      [
        edit(bytes, 'xl/worksheets/sheet1.xml', (xml) =>
          xml.replace('<v>1</v>', '<v>1payload</v>'),
        ),
        {},
        'EK_XLSX_FORMAT',
      ],
    ];
    for (const [index, [input, config, expected]] of samples.entries())
      await assert.rejects(
        f.service.open(input, config),
        code(expected),
        'Invalid archive case ' + index,
      );
  } finally {
    await f.close();
  }
});
test('Controlled styles, shapes and formula ingress reject accessors, scripts and resource abuse', () => {
  const p = options({ formulaPolicy: 'preserve' });
  for (const input of [
    { formula: '1', value: 1 },
    { value: 1, extra: true },
    { value: { value: 1 } },
    { value: 1, style: { fontColorHex: 'red' } },
    Object.defineProperty({}, 'value', {
      enumerable: true,
      get() {
        throw new Error('Accessor must not execute');
      },
    }),
  ])
    assert.throws(() => cell(input, p));
  for (const expression of [
    'HYPERLINK("http://127.0.0.1", "x")',
    '[external.xlsx]Sheet1!A1',
    '=1+1',
    'WEBSERVICE("http://127.0.0.1")',
  ])
    assert.throws(() => formula(expression), code('EK_XLSX_UNSUPPORTED'));
  for (const numberFormat of ['javascript:alert(1)', '"unterminated', '[Red', '<script>'])
    assert.throws(() => style({ numberFormat }));
  assert.throws(() => row(Array(80).fill('x'.repeat(32767)), p), code('EK_XLSX_LIMIT'));
  assert.equal(value(cell({ value: 1, style: { fontColorHex: '#abcdef' } }, p)), 1);
});
test('One-shot random access stages only by explicit opt-in in a private directory and always removes its file', async () => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-xlsx-test-')),
    f = fixture(),
    bytes = await native();
  await chmod(root, 0o700);
  async function* source() {
    yield bytes.subarray(0, 100);
    const files = await readdir(root);
    assert.equal(files.length, 1);
    assert.equal((await stat(join(root, files[0]!))).mode & 0o777, 0o600);
    yield bytes.subarray(100);
  }
  const temporaryStorage = { directory: root, maxBytes: 1048576, cleanup: 'always' as const };
  try {
    const reader = await f.service.open(source(), { readMode: 'random-access', temporaryStorage });
    assert.deepEqual(await readdir(root), []);
    assert.equal((await collect(reader.rows('Data'))).length, 1);
    await reader.close();
    await assert.rejects(
      f.service.open(source(), {
        readMode: 'random-access',
        temporaryStorage: { ...temporaryStorage, maxBytes: 101 },
      }),
      code('EK_XLSX_LIMIT'),
    );
    assert.deepEqual(await readdir(root), []);
    const link = root + '-link';
    await symlink(root, link);
    try {
      await assert.rejects(
        f.service.open(source(), {
          readMode: 'random-access',
          temporaryStorage: { ...temporaryStorage, directory: link },
        }),
        code('EK_XLSX_UNSUPPORTED'),
      );
    } finally {
      await rm(link);
    }
    await chmod(root, 0o755);
    await assert.rejects(
      f.service.open(source(), { readMode: 'random-access', temporaryStorage }),
      code('EK_XLSX_UNSUPPORTED'),
    );
  } finally {
    await f.close();
    await rm(root, { recursive: true, force: true });
  }
});
test('Timeout retains uncooperative input admission until settlement and drain waits truthfully', async () => {
  const f = fixture({ policy: { maxConcurrent: 1, timeoutMs: 50 } });
  let release!: (value: IteratorResult<Uint8Array>) => void,
    attempted = false;
  const source = {
    [Symbol.asyncIterator]() {
      return {
        next() {
          attempted = true;
          return new Promise<IteratorResult<Uint8Array>>((resolve) => {
            release = resolve;
          });
        },
        async return() {
          return { done: true as const, value: undefined };
        },
      };
    },
  };
  try {
    await assert.rejects(f.service.open(source), code('EK_TIMEOUT'));
    assert.equal(attempted, true);
    assert.throws(() => f.service.create(), code('EK_XLSX_LIMIT'));
    let drained = false;
    const closing = f.close().then(() => {
      drained = true;
    });
    await delay(20);
    assert.equal(drained, false);
    release({ done: true, value: undefined });
    await closing;
    assert.equal(drained, true);
  } finally {
    release?.({ done: true, value: undefined });
    await f.close();
  }
});
test('Application abort rejects pending input promptly and target failures expose unknown output outcome', async () => {
  const f = fixture();
  let release!: (value: IteratorResult<Uint8Array>) => void;
  const waiting = f.service.open({
    [Symbol.asyncIterator]() {
      return {
        next() {
          return new Promise<IteratorResult<Uint8Array>>((resolve) => {
            release = resolve;
          });
        },
      };
    },
  });
  await delay(10);
  f.controller.abort();
  await assert.rejects(waiting, code('EK_ABORTED'));
  release({ done: true, value: undefined });
  await f.close();
  const other = fixture();
  try {
    const writer = other.service.create();
    await writer.addSheet('Data').addRows([[1]]);
    await assert.rejects(
      writer.write(async () => {
        throw new Error('Private downstream failure');
      }),
      (error) =>
        error instanceof KitError &&
        error.details?.outcome === 'unknown' &&
        !error.message.includes('Private'),
    );
    await writer.close();
  } finally {
    await other.close();
  }
});
test('Output byte and style fidelity limits fail explicitly, including unsupported theme tint', async () => {
  const f = fixture({ policy: { maxConcurrent: 1, timeoutMs: 10000, maxOutputBytes: 100 } });
  try {
    const writer = f.service.create();
    await assert.rejects(async () => {
      await writer.addSheet('Data').addRows([[1]]);
      await writer.write(async () => undefined);
    }, code('EK_XLSX_LIMIT'));
    await writer.close();
  } finally {
    await f.close();
  }
  const other = fixture();
  try {
    const workbook = new ExcelJS.Workbook(),
      sheet = workbook.addWorksheet('Data');
    sheet.getCell('A1').value = 1;
    sheet.getCell('A1').font = { color: { theme: 1 } };
    const reader = await other.service.open(Buffer.from(await workbook.xlsx.writeBuffer()));
    const cells = (await collect(reader.rows('Data')))[0]!.cells,
      styled = cells[0]!;
    assert.ok(styled && typeof styled === 'object' && 'style' in styled);
    assert.equal(styled.style?.fontColorHex, '#000000');
    await reader.close();
    const tinted = edit(Buffer.from(await workbook.xlsx.writeBuffer()), 'xl/styles.xml', (xml) =>
      xml.replaceAll('theme="1"', 'theme="1" tint="0.5"'),
    );
    const unsupported = await other.service.open(tinted);
    await assert.rejects(collect(unsupported.rows('Data')), code('EK_XLSX_UNSUPPORTED'));
    await unsupported.close();
  } finally {
    await other.close();
  }
});
test('Paused cursor deadlines kill native work and reject concurrent next calls without a queue', async () => {
  const f = fixture();
  try {
    const reader = await f.service.open(await native([[1], [2]])),
      cursor = reader.rows('Data', { timeoutMs: 1000 })[Symbol.asyncIterator]();
    const first = cursor.next();
    await assert.rejects(cursor.next(), code('EK_XLSX_UNSUPPORTED'));
    await first;
    await delay(1050);
    await assert.rejects(cursor.next(), code('EK_TIMEOUT'));
    await reader.close();
  } finally {
    await f.close();
  }
});
test('Explicit temporary storage is cleaned after cancellation and corrupt staged input', async () => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-xlsx-abort-')),
    f = fixture(),
    bytes = await native(),
    controller = new AbortController();
  await chmod(root, 0o700);
  const config = {
    readMode: 'random-access' as const,
    temporaryStorage: { directory: root, maxBytes: 1048576, cleanup: 'always' as const },
  };
  try {
    await assert.rejects(
      f.service.open(
        {
          async *[Symbol.asyncIterator]() {
            yield Buffer.from('corrupt');
          },
        },
        config,
      ),
      code('EK_XLSX_FORMAT'),
    );
    assert.deepEqual(await readdir(root), []);
    const source = {
      async *[Symbol.asyncIterator]() {
        yield bytes.subarray(0, 100);
        controller.abort();
        yield bytes.subarray(100);
      },
    };
    await assert.rejects(
      f.service.open(source, { ...config, signal: controller.signal }),
      code('EK_ABORTED'),
    );
    await f.close();
    assert.deepEqual(await readdir(root), []);
  } finally {
    await f.close();
    await rm(root, { recursive: true, force: true });
  }
});
test('A cancelled uncooperative target retains admission and does not acknowledge a successful output', async () => {
  const f = fixture({ policy: { maxConcurrent: 1, timeoutMs: 10000 } }),
    controller = new AbortController();
  let release!: () => void, entered!: () => void;
  const began = new Promise<void>((resolve) => {
    entered = resolve;
  });
  try {
    const writer = f.service.create();
    await writer.addSheet('Data').addRows([[1]]);
    const writing = writer.write(
      async () => {
        entered();
        await new Promise<void>((resolve) => {
          release = resolve;
        });
      },
      { signal: controller.signal },
    );
    await began;
    controller.abort();
    await assert.rejects(
      writing,
      (error) =>
        error instanceof KitError &&
        error.code === 'EK_ABORTED' &&
        error.details?.outcome === 'unknown',
    );
    assert.throws(() => f.service.create(), code('EK_XLSX_LIMIT'));
    let drained = false;
    const closing = f.close().then(() => {
      drained = true;
    });
    await delay(20);
    assert.equal(drained, false);
    release();
    await closing;
    await writer.close();
  } finally {
    release?.();
    await f.close();
  }
});
test('Strict deployment and operation options reject forged signals, undefined policies and unsafe formula stripping', async () => {
  for (const config of [
    undefined,
    {},
    { defaults: {}, policy: { maxConcurrent: 0, timeoutMs: 1 } },
    { defaults: {}, policy: { maxConcurrent: 1, timeoutMs: Infinity } },
    { defaults: { maxSheets: 257 }, policy: { maxConcurrent: 1, timeoutMs: 1 } },
    {
      defaults: { temporaryStorage: { directory: 'relative', maxBytes: 1, cleanup: 'always' } },
      policy: { maxConcurrent: 1, timeoutMs: 1 },
    },
  ])
    assert.throws(() => capture(config as DataXlsxPluginSettings), code('EK_CONFIG_INVALID'));
  assert.throws(
    () =>
      cell(
        { formula: 'HYPERLINK("file:///private", "x")', cachedValue: 'x' },
        options({ formulaPolicy: 'strip' }),
      ),
    code('EK_XLSX_UNSUPPORTED'),
  );
  const f = fixture();
  try {
    await assert.rejects(
      f.service.open(new Uint8Array(), { signal: { aborted: false } as AbortSignal }),
    );
    const signal = new AbortController().signal;
    Object.defineProperty(signal, 'aborted', { value: false });
    await assert.rejects(f.service.open(new Uint8Array(), { signal }));
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      f.service.open(new Uint8Array(), { signal: controller.signal }),
      code('EK_ABORTED'),
    );
    assert.throws(() => f.service.create({ formulaPolicy: 'evaluate' as 'reject' }));
    const writer = f.service.create();
    await writer.close();
  } finally {
    await f.close();
  }
});
