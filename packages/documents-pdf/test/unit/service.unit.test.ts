// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtemp, copyFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PDFDocument, PDFName, PDFString, PDFHexString, degrees } from 'pdf-lib';
import { KitError, createApplication } from '@arkenivajs/core';
import { documentsPdfPlugin, PDF_CAPABILITY } from '../../dist/index.js';
import type { PdfService, DocumentsPdfPluginSettings } from '../../dist/index.js';
import { managedService } from '../../dist/service.js';
import { capture } from '../../dist/settings.js';

const settings = (): DocumentsPdfPluginSettings => ({
  defaults: {},
  fontAllowlist: ['Helvetica'],
  policy: { maxConcurrent: 2, timeoutMs: 10000 },
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function fixture(config = settings()) {
  const controller = new AbortController(),
    managed = managedService(capture(config), controller.signal, () => true);
  return { ...managed, controller };
}
async function source(signed = false, active = false) {
  const document = await PDFDocument.create();
  document.addPage();
  document.setTitle('Fixture\nTitle');
  document.setAuthor('Fixture Author');
  if (signed) {
    const signature = document.context.obj({
      Type: 'Sig',
      Filter: 'Adobe.PPKLite',
      SubFilter: 'adbe.pkcs7.detached',
      ByteRange: [0, 1, 2, 3],
      Contents: PDFHexString.of('0123'),
    });
    document.catalog.set(
      PDFName.of('Perms'),
      document.context.obj({ DocMDP: document.context.register(signature) }),
    );
  }
  if (active)
    document.catalog.set(
      PDFName.of('OpenAction'),
      document.context.obj({
        S: 'JavaScript',
        JS: PDFString.of('throw new Error("Must not execute")'),
      }),
    );
  return new Uint8Array(await document.save());
}
test('Public isolated PDF operations return typed metadata, text positions and independent binary output', async () => {
  const f = fixture();
  try {
    const builder = f.service.create();
    builder.addText('Protocol 123', 1, 40, 80, {
      font: 'Helvetica',
      size: 12,
      colorHex: '#112233',
    });
    const created = await builder.save(),
      original = Buffer.from(created),
      info = await f.service.inspect(created);
    assert.deepEqual(
      { pages: info.pages, encrypted: info.encrypted, signed: info.signed },
      { pages: 1, encrypted: false, signed: false },
    );
    const extracted = await f.service.extractText(created),
      first = extracted[0]!.items[0]!;
    assert.equal(first.text, 'Protocol 123');
    assert.equal(first.x, 40);
    assert.equal(first.y, 80);
    assert.ok(first.width > 0);
    assert.ok(first.height > 0);
    const edited = await f.service.addText(created, {
      page: 1,
      text: 'Rotated',
      x: 100,
      y: 100,
      font: 'Helvetica',
      size: 14,
      colorHex: '#000000',
      rotationDegrees: 90,
    });
    assert.ok(
      (await f.service.extractText(edited))[0]!.items.some((item) => item.text.includes('Rotated')),
    );
    assert.equal((await f.service.inspect(await f.service.merge([created, edited]))).pages, 2);
    assert.ok(Buffer.from(created).equals(original));
  } finally {
    await f.close();
  }
});
test('Native object-graph signature detection denies both rewriting operations independently', async () => {
  const f = fixture(),
    signed = await source(true),
    clean = await source();
  try {
    assert.equal((await f.service.inspect(signed)).signed, true);
    await assert.rejects(f.service.merge([clean, signed]), code('EK_PDF_SIGNED'));
    await assert.rejects(
      f.service.addText(signed, {
        page: 1,
        text: 'Denied',
        x: 40,
        y: 40,
        font: 'Helvetica',
        size: 12,
        colorHex: '#000000',
      }),
      code('EK_PDF_SIGNED'),
    );
    const ordinary = await PDFDocument.create();
    ordinary.addPage();
    ordinary.setTitle('/Type /Sig /ByteRange [0 1 2 3]');
    assert.equal((await f.service.inspect(new Uint8Array(await ordinary.save()))).signed, false);
  } finally {
    await f.close();
  }
});
test('Metadata sanitation and active-content denial do not execute document actions', async () => {
  const f = fixture(),
    bytes = await source(false, true);
  try {
    const info = await f.service.inspect(bytes);
    assert.equal(info.title, 'FixtureTitle');
    assert.equal(info.author, 'Fixture Author');
    await assert.rejects(f.service.merge([bytes]), code('EK_PDF_PARSE'));
    await assert.rejects(
      f.service.addText(bytes, {
        page: 1,
        text: 'Denied',
        x: 0,
        y: 0,
        font: 'Helvetica',
        size: 12,
        colorHex: '#000000',
      }),
      code('EK_PDF_PARSE'),
    );
    assert.deepEqual((await f.service.extractText(bytes))[0]!.items, []);
  } finally {
    await f.close();
  }
});
test('Public custom fonts preserve Unicode and RTL through owned native workers', async () => {
  const require = createRequire(import.meta.url),
    greek = require.resolve('@fontsource/noto-sans/files/noto-sans-greek-400-normal.woff'),
    hebrew =
      require.resolve('@fontsource/noto-sans-hebrew/files/noto-sans-hebrew-hebrew-400-normal.woff');
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-pdf-fonts-'));
  const greekFile = join(root, 'greek.woff'),
    hebrewFile = join(root, 'hebrew.woff');
  await copyFile(greek, greekFile);
  await copyFile(hebrew, hebrewFile);
  await chmod(greekFile, 0o600);
  await chmod(hebrewFile, 0o600);
  const f = fixture({ ...settings(), fontAllowlist: [greekFile, hebrewFile] });
  try {
    const builder = f.service.create();
    builder.addText('Αθήνα', 1, 40, 100, { font: greekFile, size: 12, colorHex: '#000000' });
    builder.addText('שלום', 1, 40, 80, { font: hebrewFile, size: 12, colorHex: '#000000' });
    const pages = await f.service.extractText(await builder.save()),
      text = pages[0]!.items.map((item) => item.text).join(' ');
    assert.ok(text.includes('Αθήνα'));
    assert.ok(text.includes('שלום'));
  } finally {
    await f.close();
    await rm(root, { recursive: true, force: true });
  }
});
test('Bounds reject page, input, output, text-item and builder growth instead of truncating results', async () => {
  const f = fixture();
  try {
    const builder = f.service.create();
    builder.addText('One', 1, 40, 40, { font: 'Helvetica', size: 12, colorHex: '#000000' });
    builder.addText('Two', 2, 40, 40, { font: 'Helvetica', size: 12, colorHex: '#000000' });
    const bytes = await builder.save();
    await assert.rejects(f.service.inspect(bytes, { maxBytes: 10 }), code('EK_PDF_LIMIT'));
    await assert.rejects(f.service.inspect(bytes, { maxPages: 1 }), code('EK_PDF_LIMIT'));
    await assert.rejects(f.service.extractText(bytes, { maxTextItems: 1 }), code('EK_PDF_LIMIT'));
    await assert.rejects(f.service.merge([bytes, bytes], { maxPages: 3 }), code('EK_PDF_LIMIT'));
    const limited = f.service.create({ maxPages: 1, maxTextItems: 1 });
    assert.throws(
      () =>
        limited.addText('Denied', 2, 0, 0, { font: 'Helvetica', size: 12, colorHex: '#000000' }),
      code('EK_PDF_LIMIT'),
    );
    limited.addText('One', 1, 0, 0, { font: 'Helvetica', size: 12, colorHex: '#000000' });
    assert.throws(
      () => limited.addText('Two', 1, 0, 0, { font: 'Helvetica', size: 12, colorHex: '#000000' }),
      code('EK_PDF_LIMIT'),
    );
    for (const input of [new Uint8Array(), Buffer.from('Malformed PDF'), bytes.subarray(0, 20)])
      await assert.rejects(f.service.inspect(input), code('EK_PDF_PARSE'));
  } finally {
    await f.close();
  }
});
test('Native page rotation remains intact after composition and searchable additions', async () => {
  const f = fixture(),
    original = await PDFDocument.create(),
    page = original.addPage([300, 400]);
  page.setRotation(degrees(90));
  try {
    const edited = await f.service.addText(new Uint8Array(await original.save()), {
      page: 1,
      text: 'Rotation',
      x: 30,
      y: 50,
      font: 'Helvetica',
      size: 12,
      colorHex: '#000000',
    });
    const document = await PDFDocument.load(edited);
    assert.equal(document.getPage(0).getRotation().angle, 90);
    assert.ok(
      (await f.service.extractText(edited))[0]!.items.some((item) => item.text === 'Rotation'),
    );
  } finally {
    await f.close();
  }
});
test('Application readiness and shutdown own active PDF children and prohibit use after close', async () => {
  const app = await createApplication({
    service: { name: 'pdf-fixture', version: '1.0.0', environment: 'test' },
    plugins: [documentsPdfPlugin(settings())],
  });
  try {
    await app.start();
    const pdf = app.resolve<PdfService>(PDF_CAPABILITY),
      source = pdf.create();
    const bytes = await source.save();
    assert.equal((await pdf.inspect(bytes)).pages, 1);
    await app.stop();
    assert.throws(() => pdf.create(), code('EK_RESOURCE_CLOSED'));
  } finally {
    await app.stop();
  }
});
test('Indirect native signature and action names remain protected and missing font glyphs fail explicitly', async () => {
  const f = fixture();
  try {
    const document = await PDFDocument.create(),
      signatureName = document.context.register(PDFName.of('Sig'));
    document.addPage();
    document.catalog.set(
      PDFName.of('Perms'),
      document.context.obj({
        DocMDP: document.context.register(
          document.context.obj({
            Type: signatureName,
            Contents: PDFHexString.of('0123'),
            ByteRange: [0, 1, 2, 3],
          }),
        ),
      }),
    );
    const bytes = new Uint8Array(await document.save());
    assert.equal((await f.service.inspect(bytes)).signed, true);
    await assert.rejects(f.service.merge([bytes]), code('EK_PDF_SIGNED'));
    const active = await PDFDocument.create(),
      page = active.addPage();
    const action = active.context.register(
      active.context.obj({
        S: active.context.register(PDFName.of('Launch')),
        F: PDFString.of('never-execute'),
      }),
    );
    page.node.set(
      PDFName.of('Annots'),
      active.context.obj([
        active.context.register(
          active.context.obj({ Type: 'Annot', Subtype: 'Link', Rect: [0, 0, 10, 10], A: action }),
        ),
      ]),
    );
    await assert.rejects(
      f.service.merge([new Uint8Array(await active.save())]),
      code('EK_PDF_PARSE'),
    );
    const builder = f.service.create();
    builder.addText('漢字', 1, 0, 0, { font: 'Helvetica', size: 12, colorHex: '#000000' });
    await assert.rejects(builder.save(), code('EK_PDF_PARSE'));
  } finally {
    await f.close();
  }
});
