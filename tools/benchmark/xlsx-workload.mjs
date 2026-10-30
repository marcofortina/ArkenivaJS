// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import ExcelJS from 'exceljs';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';
import { xlsxFixtureBytes, xlsxFixtureSha256 } from './xlsx-fixture.mjs';

const readSamples = new WeakMap();

export function prepareXlsxRead(service, fixture) {
  assert.equal(readSamples.has(service), false);
  assert.equal(createHash('sha256').update(xlsxFixtureBytes).digest('hex'), xlsxFixtureSha256);
  readSamples.set(service, { fixture, results: [], active: false, closed: false });
}

export function xlsxReadWorkload(service) {
  const state = readSamples.get(service);
  assert.ok(state);
  return {
    async readFiveRows() {
      assert.equal(state.closed, false);
      assert.equal(state.active, false);
      assert.ok(state.results.length < 120);
      state.active = true;
      try {
        const result = await readWorkbook(service, xlsxFixtureBytes, state.fixture, true);
        state.results.push(result);
        return result;
      } finally {
        state.active = false;
      }
    },
  };
}

export function completeXlsxRead(service, { measure, records }) {
  const state = readSamples.get(service);
  try {
    if (!measure) {
      assert.equal(state, undefined);
      assert.deepEqual(records, []);
      return { sampledReads: 0, warmupReads: 0, checkedReads: 0 };
    }
    assert.ok(state);
    assert.equal(state.active, false);
    assert.equal(records.length, 1);
    const record = records[0];
    assert.equal(record.operation, 'readFiveRows');
    assert.equal(record.sampleCount, 100);
    assert.equal(record.warmupIterations, 20);
    assert.equal(record.rawLatency.unit, 'milliseconds');
    assert.equal(record.rawLatency.values.length, 100);
    assert.equal(state.results.length, 120);
    for (const value of state.results) {
      assert.equal(value.checkedSheets, 2);
      assert.equal(value.checkedRows, 5);
      assert.equal(value.sourceTraversals, 1);
      assert.equal(value.inputBytes, xlsxFixtureBytes.length);
      assert.equal(value.sourceRetired, true);
      assert.equal(value.readerClosed, true);
      assert.ok(Number.isFinite(value.firstRowMs) && value.firstRowMs >= 0);
      assert.ok(Number.isFinite(value.elapsedMs) && value.elapsedMs >= value.firstRowMs);
      assert.ok(Number.isFinite(value.rowsPerSecond) && value.rowsPerSecond > 0);
    }
    assert.equal(createHash('sha256').update(xlsxFixtureBytes).digest('hex'), xlsxFixtureSha256);
    return {
      sampledReads: 100,
      warmupReads: 20,
      checkedReads: 120,
      fixedInputSha256: xlsxFixtureSha256,
      measurements: [...state.results],
      maximumRetainedResults: 128,
      inputUnchanged: true,
      opaqueNativeBufferBytes: null,
    };
  } finally {
    if (state) {
      state.closed = true;
      state.results.length = 0;
    }
    readSamples.delete(service);
  }
}

export const xlsxSettings = {
  defaults: {
    maxSheets: 2,
    maxRowsPerSheet: 16,
    maxCells: 128,
    maxUncompressedBytes: 1048576,
    formulaPolicy: 'preserve',
    readMode: 'stream',
  },
  policy: { maxConcurrent: 2, timeoutMs: 10000, maxInputBytes: 1048576, maxOutputBytes: 1048576 },
};

function corpus(fixture) {
  return [
    {
      name: fixture.firstSheet,
      rows: [
        ['id', 'name', 'active', 'amount'],
        [
          '001',
          fixture.marker,
          true,
          {
            value: 123.45,
            style: { numberFormat: '#,##0.00', bold: true, fontColorHex: '#123456' },
          },
        ],
        [
          '=1+2',
          '€ λ',
          false,
          null,
          new Date('2026-01-02T03:04:05.000Z'),
          { formula: '1+2', cachedValue: 99 },
        ],
      ],
    },
    { name: fixture.secondSheet, rows: [[fixture.marker], [0, null, false, 'last']] },
  ];
}
const unwrapped = (cell) =>
  cell && typeof cell === 'object' && !(cell instanceof Date) && 'value' in cell
    ? cell.value
    : cell;
const canonical = (value) => JSON.parse(JSON.stringify(value));

/** The bounded native object-model baseline verifies interoperability, not equivalent streaming cost. */
export function nativeXlsx() {
  return {
    create() {
      const book = new ExcelJS.Workbook();
      let rows = 0,
        closed = false;
      return {
        addSheet(name) {
          assert.equal(closed, false);
          const sheet = book.addWorksheet(name);
          return {
            async addRows(input) {
              for await (const row of input) {
                const nativeRow = sheet.addRow([]);
                for (const [index, item] of row.entries()) {
                  const value = unwrapped(item),
                    cell = nativeRow.getCell(index + 1);
                  cell.value =
                    value && typeof value === 'object' && !(value instanceof Date)
                      ? { formula: value.formula, result: value.cachedValue }
                      : value;
                  if (item?.style) {
                    cell.numFmt = item.style.numberFormat;
                    cell.font = {
                      bold: item.style.bold,
                      color: { argb: 'FF' + item.style.fontColorHex.slice(1) },
                    };
                  }
                }
                rows++;
              }
            },
          };
        },
        async write(target) {
          assert.equal(closed, false);
          const bytes = Buffer.from(await book.xlsx.writeBuffer());
          assert.ok(bytes.length <= 1048576);
          await target(bytes);
          return {
            sheetCount: book.worksheets.length,
            writtenRows: rows,
            outputBytes: bytes.length,
          };
        },
        async close() {
          closed = true;
        },
      };
    },
    async open(source) {
      const chunks = [];
      let size = 0;
      if (source instanceof Uint8Array) chunks.push(source);
      else
        for await (const chunk of source) {
          size += chunk.length;
          assert.ok(size <= 1048576);
          chunks.push(chunk);
        }
      const book = new ExcelJS.Workbook();
      await book.xlsx.load(Buffer.concat(chunks));
      return {
        sheetNames: book.worksheets.map((sheet) => sheet.name),
        async *rows(name) {
          const sheet = book.getWorksheet(name);
          assert.ok(sheet);
          for (let index = 1; index <= sheet.rowCount; index++) {
            const row = sheet.getRow(index),
              cells = [];
            for (let column = 1; column <= row.cellCount; column++) {
              const cell = row.getCell(column);
              let value = cell.value;
              if (value && typeof value === 'object' && !(value instanceof Date))
                value = { formula: value.formula, cachedValue: value.result ?? null };
              const style = {};
              if (cell.numFmt && cell.numFmt !== 'General') style.numberFormat = cell.numFmt;
              if (cell.font?.bold !== undefined) style.bold = cell.font.bold;
              if (cell.font?.color?.argb) style.fontColorHex = '#' + cell.font.color.argb.slice(2);
              cells.push(Object.keys(style).length ? { value, style } : value);
            }
            yield { rowIndex: index, cells };
          }
        },
        async close() {},
      };
    },
  };
}

async function writeWorkbook(service, fixture) {
  const writer = service.create(),
    chunks = [];
  let size = 0,
    active = 0,
    completedTargets = 0;
  try {
    for (const sheet of corpus(fixture)) await writer.addSheet(sheet.name).addRows(sheet.rows);
    const receipt = await writer.write(async (chunk) => {
      assert.equal(++active, 1);
      try {
        size += chunk.byteLength;
        assert.ok(size <= 1048576);
        chunks.push(Buffer.from(chunk));
        await setImmediate();
        completedTargets++;
      } finally {
        active--;
      }
    });
    assert.equal(active, 0);
    assert.ok(completedTargets > 0);
    assert.deepEqual(receipt, { sheetCount: 2, writtenRows: 5, outputBytes: size });
    assert.ok(size > 500);
    return Buffer.concat(chunks);
  } finally {
    await writer.close();
  }
}

async function readWorkbook(service, bytes, fixture, fragmented) {
  const started = performance.now();
  let traversals = 0,
    firstRowMs,
    checkedRows = 0,
    sourceRetired = false;
  const source = fragmented
    ? {
        async *[Symbol.asyncIterator]() {
          assert.equal(++traversals, 1);
          try {
            for (let offset = 0; offset < bytes.length; offset += 7)
              yield bytes.subarray(offset, offset + 7);
          } finally {
            sourceRetired = true;
          }
        },
      }
    : bytes;
  const reader = await service.open(source, { formulaPolicy: 'preserve', readMode: 'stream' });
  try {
    const sheets = corpus(fixture);
    assert.deepEqual(
      [...reader.sheetNames],
      sheets.map((sheet) => sheet.name),
    );
    for (const sheet of sheets) {
      const actual = [];
      for await (const row of reader.rows(sheet.name)) {
        firstRowMs ??= performance.now() - started;
        checkedRows++;
        assert.equal(row.rowIndex, actual.length + 1);
        actual.push(row.cells);
      }
      assert.deepEqual(
        canonical(actual.map((row) => row.map(unwrapped))),
        canonical(sheet.rows.map((row) => row.map(unwrapped))),
      );
      if (sheet.name === fixture.firstSheet) {
        const styled = actual[1][3];
        assert.equal(styled.style.numberFormat, '#,##0.00');
        assert.equal(styled.style.bold, true);
        assert.equal(styled.style.fontColorHex, '#123456');
        const date = unwrapped(actual[2][4]);
        assert.ok(date instanceof Date);
        assert.equal(date.toISOString(), '2026-01-02T03:04:05.000Z');
        assert.deepEqual(canonical(unwrapped(actual[2][5])), { formula: '1+2', cachedValue: 99 });
      }
    }
    if (fragmented) assert.equal(traversals, 1);
  } finally {
    await reader.close();
  }
  const elapsedMs = performance.now() - started;
  return {
    checkedSheets: 2,
    checkedRows,
    firstRowMs,
    elapsedMs,
    rowsPerSecond: (checkedRows * 1000) / elapsedMs,
    inputBytes: bytes.length,
    sourceTraversals: traversals,
    sourceRetired,
    readerClosed: true,
  };
}

export async function verifyXlsx(service, fixture) {
  const native = nativeXlsx(),
    nativeBytes = await writeWorkbook(native, fixture);
  await readWorkbook(service, nativeBytes, fixture, true);
  const output = await writeWorkbook(service, fixture);
  await readWorkbook(native, output, fixture, false);
  return {
    sheetsPerWorkbook: 2,
    rowsPerWorkbook: 5,
    nativeToPublicRead: true,
    publicToNativeRead: true,
    oneShotSourceVerified: true,
    awaitedTargetsVerified: true,
    formulasUnexecuted: true,
    styleAndDateVerified: true,
  };
}
