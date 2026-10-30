// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import ExcelJS from 'exceljs';
import { unzipSync, zipSync, strToU8 } from 'fflate';
import { KitError } from '@arkenivajs/core';
import { inspect } from '../../dist/archive.js';
import { options } from '../../dist/settings.js';

async function archive() {
  const workbook = new ExcelJS.Workbook();
  workbook.addWorksheet('Data').addRow([1]);
  return unzipSync(new Uint8Array(await workbook.xlsx.writeBuffer()));
}
const sheet = 'xl/worksheets/sheet1.xml';
function document(parts: Record<string, Uint8Array>, name: string, xml: string) {
  return Buffer.from(zipSync({ ...parts, [name]: strToU8(xml) }));
}
function worksheet(body: string) {
  return `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">${body}</worksheet>`;
}
function cell(body: string, attributes = '') {
  return worksheet(`<sheetData><row r="1"><c r="A1" ${attributes}>${body}</c></row></sheetData>`);
}
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('XLSX archive gate rejects malformed addresses, row order and unsupported cell semantics before native decoding', async () => {
  const parts = await archive();
  const cases: Array<[string, string]> = [
    [
      worksheet('<sheetData><row r="1"><c r="invalid"><v>1</v></c></row></sheetData>'),
      'EK_XLSX_FORMAT',
    ],
    [
      worksheet('<sheetData><row r="1"><c r="XFE1"><v>1</v></c></row></sheetData>'),
      'EK_XLSX_LIMIT',
    ],
    [worksheet('<sheetData><row r="0"/></sheetData>'), 'EK_XLSX_LIMIT'],
    [worksheet('<sheetData><row r="2"/><row r="1"/></sheetData>'), 'EK_XLSX_LIMIT'],
    [worksheet('<sheetData><row r="1"><c r="A2"><v>1</v></c></row></sheetData>'), 'EK_XLSX_LIMIT'],
    [worksheet('<cols><col min="2" max="1"/></cols>'), 'EK_XLSX_FORMAT'],
    [worksheet('<cols><col min="0" max="1"/></cols>'), 'EK_XLSX_LIMIT'],
    [worksheet('<hyperlinks><hyperlink location="Data!A1"/></hyperlinks>'), 'EK_XLSX_UNSUPPORTED'],
    [worksheet('<hyperlinks><hyperlink r:id="external"/></hyperlinks>'), 'EK_XLSX_UNSUPPORTED'],
    [cell('<v>#VALUE!</v>', 't="e"'), 'EK_XLSX_UNSUPPORTED'],
    [cell('<v>2026-01-01</v>', 't="d"'), 'EK_XLSX_UNSUPPORTED'],
    [cell('<v>1</v>', 't="unknown"'), 'EK_XLSX_UNSUPPORTED'],
    [cell('<v>-1</v>', 't="s"'), 'EK_XLSX_FORMAT'],
    [cell('<v>99999999999999999999</v>', 't="s"'), 'EK_XLSX_FORMAT'],
    [cell('<v>1e999</v>'), 'EK_XLSX_FORMAT'],
    [cell('<v>2</v>', 't="b"'), 'EK_XLSX_FORMAT'],
    [cell('<is><t>one</t><t>two</t></is>', 't="inlineStr"'), 'EK_XLSX_UNSUPPORTED'],
    [cell(`<is><t>${'x'.repeat(32768)}</t></is>`, 't="inlineStr"'), 'EK_XLSX_LIMIT'],
    [cell(`<f>${'1'.repeat(8193)}</f><v>1</v>`), 'EK_XLSX_LIMIT'],
    [cell(`<v>${'1'.repeat(131069)}</v>`, 't="str"'), 'EK_XLSX_LIMIT'],
    [cell('<f/><v>1</v>'), 'EK_XLSX_UNSUPPORTED'],
    [cell('<f t="shared">1</f><v>1</v>'), 'EK_XLSX_UNSUPPORTED'],
  ];
  for (const [index, [xml, expected]] of cases.entries())
    await assert.rejects(
      inspect(document(parts, sheet, xml), options({ formulaPolicy: 'preserve' })),
      code(expected),
      `Workbook cell boundary ${index}`,
    );
  for (const xml of [
    cell('<v>0</v>', 't="b"'),
    cell('<v>0</v>', 't="s"'),
    cell('<v>+1.5e2</v>'),
    cell('<v>literal</v>', 't="str"'),
  ])
    assert.equal((await inspect(document(parts, sheet, xml), options())).cells, 1);
});
test('XLSX archive gate bounds XML structure, encoding, attributes and style records', async () => {
  const parts = await archive();
  const cases: Array<[string, string, string]> = [
    [sheet, '<?xml version="1.0" encoding="UTF-16"?>' + worksheet(''), 'EK_XLSX_UNSUPPORTED'],
    [sheet, '<worksheet><unclosed></worksheet>', 'EK_XLSX_FORMAT'],
    [sheet, worksheet('<x>'.repeat(65) + '</x>'.repeat(65)), 'EK_XLSX_LIMIT'],
    [
      sheet,
      worksheet(`<x ${Array.from({ length: 65 }, (_, index) => `a${index}="x"`).join(' ')}/>`),
      'EK_XLSX_LIMIT',
    ],
    [sheet, worksheet(`<${'x'.repeat(257)}/>`), 'EK_XLSX_LIMIT'],
    [sheet, worksheet(`<x ${'a'.repeat(257)}="x"/>`), 'EK_XLSX_LIMIT'],
    [sheet, worksheet(`<x a="${'x'.repeat(16385)}"/>`), 'EK_XLSX_LIMIT'],
    ['xl/styles.xml', '<styleSheet><fonts count="invalid"/></styleSheet>', 'EK_XLSX_LIMIT'],
    ['xl/styles.xml', '<styleSheet><fills count="4097"/></styleSheet>', 'EK_XLSX_LIMIT'],
    ['xl/styles.xml', '<styleSheet><numFmts count="257"/></styleSheet>', 'EK_XLSX_LIMIT'],
    [
      'xl/styles.xml',
      '<styleSheet><cellXfs>' + '<xf/>'.repeat(4097) + '</cellXfs></styleSheet>',
      'EK_XLSX_LIMIT',
    ],
    [
      'xl/_rels/workbook.xml.rels',
      '<Relationships><Relationship Target="http://untrusted.invalid"/></Relationships>',
      'EK_XLSX_UNSUPPORTED',
    ],
    [
      'xl/_rels/workbook.xml.rels',
      '<Relationships><Relationship Target="\\foreign"/></Relationships>',
      'EK_XLSX_UNSUPPORTED',
    ],
    [
      'xl/_rels/workbook.xml.rels',
      '<Relationships><Relationship Type="http://schemas.invalid/hyperlink"/></Relationships>',
      'EK_XLSX_UNSUPPORTED',
    ],
    [
      'xl/_rels/workbook.xml.rels',
      `<Relationships><Relationship Target="${'x'.repeat(2049)}"/></Relationships>`,
      'EK_XLSX_FORMAT',
    ],
    [
      '[Content_Types].xml',
      '<Types><Override ContentType="application/macroEnabled"/></Types>',
      'EK_XLSX_UNSUPPORTED',
    ],
    [
      'xl/workbook.xml',
      '<workbook><sheets><sheet name="Data"/><sheet name="data"/></sheets></workbook>',
      'EK_XLSX_LIMIT',
    ],
  ];
  for (const [index, [name, xml, expected]] of cases.entries())
    await assert.rejects(
      inspect(document(parts, name, xml), options()),
      code(expected),
      `Workbook XML boundary ${index}`,
    );
  const source = { ...parts };
  delete source['xl/workbook.xml'];
  await assert.rejects(inspect(Buffer.from(zipSync(source)), options()), code('EK_XLSX_FORMAT'));
});
test('XLSX archive gate validates entry identity, declared expansion and required metadata', async () => {
  const parts = await archive();
  for (const name of [
    'XL/WORKBOOK.XML',
    '/absolute.xml',
    'folder/../escape.xml',
    'folder/./escape.xml',
    'line\nbreak.xml',
    'x'.repeat(1025),
  ])
    await assert.rejects(
      inspect(Buffer.from(zipSync({ ...parts, [name]: strToU8('<x/>') })), options()),
    );
  for (const name of ['xl/activeX/component.xml', 'xl/externalLinks/link.xml', 'xl/native.bin'])
    await assert.rejects(
      inspect(Buffer.from(zipSync({ ...parts, [name]: strToU8('<x/>') })), options()),
      code('EK_XLSX_UNSUPPORTED'),
    );
  const many = { ...parts };
  for (let index = 0; index < 300; index++) many[`empty${index}`] = new Uint8Array();
  await assert.rejects(
    inspect(Buffer.from(zipSync(many)), options({ maxSheets: 1 })),
    code('EK_XLSX_LIMIT'),
  );
  await assert.rejects(
    inspect(Buffer.from(zipSync(parts)), options({ maxUncompressedBytes: 1 })),
    code('EK_XLSX_LIMIT'),
  );
  for (const name of ['xl/_rels/workbook.xml.rels', '[Content_Types].xml']) {
    const missing = { ...parts };
    delete missing[name];
    await assert.rejects(inspect(Buffer.from(zipSync(missing)), options()), code('EK_XLSX_FORMAT'));
  }
});
