// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApplication, KitError } from '@arkenivajs/core';
import { dataXlsxPlugin, XLSX_CAPABILITY } from '../../dist/index.js';
import type { DataXlsxPluginSettings, ExcelService, XlsxCell } from '../../dist/index.js';
import { managedService } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';

const settings = (): DataXlsxPluginSettings => ({
  defaults: {},
  policy: { maxConcurrent: 2, timeoutMs: 10000 },
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
async function collect<T>(source: AsyncIterable<T>): Promise<T[]> {
  const result: T[] = [];
  for await (const value of source) result.push(value);
  return result;
}
const value = (cell: XlsxCell) =>
  cell && typeof cell === 'object' && !(cell instanceof Date) && 'value' in cell
    ? cell.value
    : cell;
function fixture(config = settings()) {
  const controller = new AbortController();
  const managed = managedService(capture(config), controller.signal, () => true);
  return { ...managed, controller };
}
async function workbook(service: ExcelService): Promise<Buffer> {
  const writer = service.create(),
    a = writer.addSheet('First'),
    b = writer.addSheet('Second');
  await a.addRows([
    ['id', 'name'],
    [1, 'λ'],
  ]);
  await b.addRows([[true, new Date('2026-01-01T00:00:00Z')]]);
  const chunks: Buffer[] = [];
  const receipt = await writer.write(async (chunk) => {
    chunks.push(Buffer.from(chunk));
  });
  assert.deepEqual(
    { sheets: receipt.sheetCount, rows: receipt.writtenRows },
    { sheets: 2, rows: 3 },
  );
  await writer.close();
  return Buffer.concat(chunks);
}
test('Isolated native XLSX workers roundtrip typed rows and enforce ordered single-pass stream access', async () => {
  const f = fixture();
  try {
    const bytes = await workbook(f.service),
      reader = await f.service.open(bytes);
    assert.deepEqual(reader.sheetNames, ['First', 'Second']);
    assert.throws(() => reader.rows('Second'), code('EK_XLSX_UNSUPPORTED'));
    const first = await collect(reader.rows('First'));
    assert.deepEqual(
      first.map((row) => row.cells.map(value)),
      [
        ['id', 'name'],
        [1, 'λ'],
      ],
    );
    assert.throws(() => reader.rows('First'), code('EK_XLSX_UNSUPPORTED'));
    const second = await collect(reader.rows('Second'));
    assert.equal(value(second[0]!.cells[0]!), true);
    assert.equal((value(second[0]!.cells[1]!) as Date).toISOString(), '2026-01-01T00:00:00.000Z');
    await reader.close();
    assert.ok(bytes.some((byte) => byte !== 0));
  } finally {
    await f.close();
  }
});
test('Random-access bytes allow sequential revisits without reopening caller sources', async () => {
  const f = fixture();
  try {
    const bytes = await workbook(f.service),
      reader = await f.service.open(bytes, { readMode: 'random-access' });
    assert.equal((await collect(reader.rows('Second'))).length, 1);
    assert.equal((await collect(reader.rows('First'))).length, 2);
    assert.equal((await collect(reader.rows('Second'))).length, 1);
    await reader.close();
    let touched = false;
    const source = {
      async *[Symbol.asyncIterator]() {
        touched = true;
        yield bytes;
      },
    };
    await assert.rejects(
      f.service.open(source, { readMode: 'random-access' }),
      code('EK_XLSX_UNSUPPORTED'),
    );
    assert.equal(touched, false);
  } finally {
    await f.close();
  }
});
test('Workbook admission, shape validation and per-row limits fail explicitly', async () => {
  const f = fixture({
    defaults: { maxCells: 2, maxRowsPerSheet: 1 },
    policy: { maxConcurrent: 1, timeoutMs: 10000 },
  });
  try {
    const writer = f.service.create();
    assert.throws(() => f.service.create(), code('EK_XLSX_LIMIT'));
    const sheet = writer.addSheet('Data');
    assert.throws(() => writer.addSheet('data'), code('EK_XLSX_LIMIT'));
    await assert.rejects(sheet.addRows([[1, 2, 3]]), code('EK_XLSX_LIMIT'));
    await writer.close();
    const next = f.service.create();
    await assert.rejects(
      next.addSheet('Values').addRows([[{ value: 1, formula: '1' } as unknown as XlsxCell]]),
      code('EK_XLSX_FORMAT'),
    );
    await next.close();
  } finally {
    await f.close();
  }
});
test('Reader early return closes its owned process and a concurrent cursor is rejected', async () => {
  const f = fixture();
  try {
    const bytes = await workbook(f.service),
      reader = await f.service.open(bytes),
      cursor = reader.rows('First')[Symbol.asyncIterator]();
    assert.equal((await cursor.next()).done, false);
    assert.throws(() => reader.rows('First'), code('EK_XLSX_UNSUPPORTED'));
    await cursor.return?.();
    assert.throws(() => reader.rows('Second'));
    await reader.close();
  } finally {
    await f.close();
  }
});
test('Application readiness and shutdown own the XLSX capability and idle workbook processes', async () => {
  const app = await createApplication({
    service: { name: 'xlsx-fixture', version: '1.0.0', environment: 'test' },
    plugins: [dataXlsxPlugin(settings())],
  });
  let service: ExcelService | undefined;
  try {
    await app.start();
    service = app.resolve<ExcelService>(XLSX_CAPABILITY);
    const bytes = await workbook(service);
    await service.open(bytes);
    await app.stop();
    assert.throws(() => service!.create(), code('EK_RESOURCE_CLOSED'));
  } finally {
    await app.stop();
  }
});
test('Thousands of streamed rows use native streaming with finite sampled worker memory and exact counts', async () => {
  const observations: number[] = [],
    controller = new AbortController();
  const f = managedService(
    capture({
      defaults: { maxRowsPerSheet: 5000, maxCells: 15000, maxUncompressedBytes: 4 * 1024 * 1024 },
      policy: { maxConcurrent: 1, timeoutMs: 30000 },
    }),
    controller.signal,
    () => true,
    {
      telemetry: {
        recordHistogram(name: string, value: number) {
          if (name === 'xlsx.worker.memory.sampled-peak.bytes') observations.push(value);
        },
      } as unknown as import('@arkenivajs/core').Telemetry,
    },
  );
  try {
    const writer = f.service.create();
    await writer.addSheet('Data').addRows(
      (function* () {
        for (let index = 0; index < 5000; index++) yield [index, 'λ-' + index, index % 2 === 0];
      })(),
    );
    const chunks: Buffer[] = [],
      receipt = await writer.write(async (chunk) => {
        chunks.push(Buffer.from(chunk));
      });
    assert.equal(receipt.writtenRows, 5000);
    const reader = await f.service.open(Buffer.concat(chunks));
    let count = 0;
    for await (const row of reader.rows('Data')) {
      assert.equal(row.rowIndex, ++count);
      assert.equal(value(row.cells[0]!), count - 1);
    }
    assert.equal(count, 5000);
    await reader.close();
    assert.ok(observations.length > 0);
    assert.ok(Math.max(...observations) < 256 * 1024 * 1024);
  } finally {
    await f.close();
  }
});
