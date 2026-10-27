// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { perform } from '../../dist/backend.js';
import { limits } from '../../dist/settings.js';
import type { Work } from '../../dist/backend.js';
import type { PdfInfo, PdfTextPage } from '../../dist/contracts.js';

test('Native PDF engines create, inspect, extract, merge and add searchable rotated text', async () => {
  const base: Work = {
    operation: 'create',
    limits: limits(),
    maximum: 1048576,
    inputs: [],
    fonts: {},
    specs: [
      {
        page: 1,
        text: 'Protocol 123',
        x: 40,
        y: 40,
        font: 'Helvetica',
        size: 12,
        colorHex: '#112233',
        rotationDegrees: 0,
      },
    ],
  };
  const created = (await perform(base)) as Uint8Array;
  assert.ok(created instanceof Uint8Array);
  const info = (await perform({ ...base, operation: 'inspect', inputs: [created] })) as PdfInfo;
  assert.equal(info.pages, 1);
  assert.equal(info.signed, false);
  const pages = (await perform({
    ...base,
    operation: 'extract',
    inputs: [created],
  })) as readonly PdfTextPage[];
  assert.equal(pages[0]!.items.map((item) => item.text).join(''), 'Protocol 123');
  const edited = (await perform({
    ...base,
    operation: 'add',
    inputs: [created],
    specs: [{ ...base.specs[0]!, text: 'Added', rotationDegrees: 90 }],
  })) as Uint8Array;
  const result = (await perform({
    ...base,
    operation: 'extract',
    inputs: [edited],
  })) as readonly PdfTextPage[];
  assert.ok(result[0]!.items.some((item) => item.text.includes('Added')));
  const merged = (await perform({
    ...base,
    operation: 'merge',
    inputs: [created, edited],
  })) as Uint8Array;
  assert.equal(
    ((await perform({ ...base, operation: 'inspect', inputs: [merged] })) as PdfInfo).pages,
    2,
  );
});
test('Native font embedding preserves searchable Greek and right-to-left Hebrew text', async () => {
  const { createRequire } = await import('node:module'),
    { readFile } = await import('node:fs/promises'),
    require = createRequire(import.meta.url);
  const greek = require.resolve('@fontsource/noto-sans/files/noto-sans-greek-400-normal.woff'),
    hebrew =
      require.resolve('@fontsource/noto-sans-hebrew/files/noto-sans-hebrew-hebrew-400-normal.woff');
  const base: Work = {
    operation: 'create',
    limits: limits(),
    maximum: 1048576,
    inputs: [],
    fonts: {
      Greek: new Uint8Array(await readFile(greek)),
      Hebrew: new Uint8Array(await readFile(hebrew)),
    },
    specs: [
      {
        page: 1,
        text: 'Αθήνα',
        x: 40,
        y: 100,
        font: 'Greek',
        size: 12,
        colorHex: '#000000',
        rotationDegrees: 0,
      },
      {
        page: 1,
        text: 'שלום',
        x: 40,
        y: 80,
        font: 'Hebrew',
        size: 12,
        colorHex: '#000000',
        rotationDegrees: 0,
      },
    ],
  };
  const created = (await perform(base)) as Uint8Array,
    pages = (await perform({
      ...base,
      operation: 'extract',
      inputs: [created],
    })) as readonly PdfTextPage[];
  const text = pages[0]!.items.map((item) => item.text).join(' ');
  assert.ok(text.includes('Αθήνα'), text);
  assert.ok(text.includes('שלום'), text);
});
