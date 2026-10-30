// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PDFDocument, StandardFonts, PDFSignature, PDFName, rgb, degrees } from 'pdf-lib';
import { pdfInspectFixture, pdfInspectExpected, pdfInspectDescriptor } from './pdf-fixture.mjs';

export const pdfFixture = Object.freeze({
  first: 'owned-pdf-private-first',
  second: 'owned-pdf-private-second',
  added: 'owned-pdf-private-added',
  title: 'owned-pdf-private-title',
});

export const pdfSettings = {
  defaults: { maxBytes: 1048576, maxPages: 8, maxTextItems: 128, maxDecodeMs: 10000 },
  fontAllowlist: ['Helvetica'],
  policy: { maxConcurrent: 2, timeoutMs: 10000, maxInputBytes: 1048576, maxOutputBytes: 1048576 },
};

async function draw(document, spec) {
  assert.equal(spec.font, 'Helvetica');
  const font = await document.embedFont(StandardFonts.Helvetica),
    hex = spec.colorHex.slice(1);
  document.getPage(spec.page - 1).drawText(spec.text, {
    x: spec.x,
    y: spec.y,
    size: spec.size,
    font,
    color: rgb(
      parseInt(hex.slice(0, 2), 16) / 255,
      parseInt(hex.slice(2, 4), 16) / 255,
      parseInt(hex.slice(4, 6), 16) / 255,
    ),
    rotate: degrees(spec.rotationDegrees ?? 0),
  });
}
async function save(document) {
  const bytes = await document.save();
  assert.ok(bytes.byteLength <= 1048576);
  return bytes;
}

async function nativeTask(source) {
  const path = import.meta.resolve('pdfjs-dist/legacy/build/pdf.mjs'),
    engine = await import(path),
    root = dirname(dirname(dirname(fileURLToPath(path))));
  return engine.getDocument({
    data: new Uint8Array(source),
    verbosity: 0,
    useWorkerFetch: false,
    standardFontDataUrl: join(root, 'standard_fonts') + sep,
    cMapUrl: join(root, 'cmaps') + sep,
    useSystemFonts: false,
    useWasm: false,
    disableFontFace: true,
    isEvalSupported: false,
    enableXfa: false,
  });
}

/** Direct pinned native engines on an explicitly small unsigned, inactive corpus. */
export function nativePdf() {
  return {
    create() {
      const specs = [];
      return {
        addText(text, page, x, y, options) {
          specs.push({ text, page, x, y, ...options });
        },
        async save() {
          const document = await PDFDocument.create();
          for (let page = 0; page < Math.max(1, ...specs.map((item) => item.page)); page++)
            document.addPage([595.28, 841.89]);
          for (const spec of specs) await draw(document, spec);
          return save(document);
        },
      };
    },
    async inspect(source) {
      const document = await PDFDocument.load(source, { updateMetadata: false });
      const signed =
        document.catalog.has(PDFName.of('Perms')) ||
        document
          .getForm()
          .getFields()
          .some((field) => field instanceof PDFSignature);
      const task = await nativeTask(source);
      try {
        const parsed = await task.promise,
          { info } = await parsed.getMetadata();
        assert.equal(parsed.numPages, document.getPageCount());
        assert.equal(info.IsEncrypted === true, document.isEncrypted);
        assert.equal(info.Title, document.getTitle());
        assert.equal(info.Author, document.getAuthor());
        return {
          pages: parsed.numPages,
          encrypted: document.isEncrypted,
          signed: signed || info.IsSignaturesPresent === true,
          ...(info.Title === undefined ? {} : { title: info.Title }),
          ...(info.Author === undefined ? {} : { author: info.Author }),
        };
      } finally {
        await task.destroy();
      }
    },
    async extractText(source) {
      const task = await nativeTask(source);
      try {
        const document = await task.promise,
          pages = [];
        for (let index = 1; index <= document.numPages; index++) {
          const page = await document.getPage(index),
            content = await page.getTextContent({ disableNormalization: true });
          pages.push({
            page: index,
            items: content.items
              .filter((item) => typeof item.str === 'string')
              .map((item) => ({
                text: item.str,
                x: item.transform[4],
                y: item.transform[5],
                width: item.width,
                height: item.height,
              })),
          });
        }
        return pages;
      } finally {
        await task.destroy();
      }
    },
    async merge(inputs) {
      const output = await PDFDocument.create();
      for (const source of inputs) {
        const document = await PDFDocument.load(source),
          pages = await output.copyPages(document, document.getPageIndices());
        for (const page of pages) output.addPage(page);
      }
      return save(output);
    },
    async addText(source, spec) {
      const document = await PDFDocument.load(source);
      await draw(document, spec);
      return save(document);
    },
  };
}

/** Inspect one fixed document per callback and independently verify every private metadata report. */
export function pdfInspectWorkload(service) {
  const source = pdfInspectFixture(),
    before = Buffer.from(source),
    reports = [];
  let inspections = 0,
    reportBytes = 0,
    completed = false;
  return {
    workload: {
      async 'inspect-fixed-one-page-pdf'() {
        assert.equal(completed, false);
        assert.ok(reports.length < 120, 'The private PDF inspection report capacity is exceeded');
        const result = await service.inspect(source);
        assert.deepEqual(result, pdfInspectExpected);
        assert.deepEqual(source, before);
        const encoded = JSON.stringify(result),
          bytes = Buffer.byteLength(encoded);
        assert.ok(bytes > 0 && bytes <= 2048 && reportBytes + bytes <= 262144);
        reports.push(encoded);
        inspections++;
        reportBytes += bytes;
        return result.pages;
      },
    },
    async complete(records) {
      assert.equal(completed, false);
      completed = true;
      try {
        assert.equal(records.length, 1);
        assert.equal(records[0].operation, 'inspect-fixed-one-page-pdf');
        const count = records[0].sampleCount + records[0].warmupIterations;
        assert.ok(Number.isSafeInteger(count) && count > 0 && count <= 120);
        assert.equal(reports.length, count);
        assert.equal(inspections, count);
        assert.deepEqual(source, before);
        const document = await PDFDocument.load(source, { updateMetadata: false }),
          text = await nativePdf().extractText(source),
          digest = createHash('sha256');
        assert.equal(document.getPageCount(), pdfInspectExpected.pages);
        assert.equal(document.isEncrypted, false);
        assert.equal(document.getTitle(), pdfInspectExpected.title);
        assert.equal(document.getAuthor(), pdfInspectExpected.author);
        assert.deepEqual(texts(text), [pdfFixture.first]);
        for (const encoded of reports) {
          assert.deepEqual(JSON.parse(encoded), pdfInspectExpected);
          digest.update(encoded);
        }
        return {
          actualInspectOperations: inspections,
          checkedInspectionReports: reports.length,
          inspectedPages: inspections * pdfInspectDescriptor.pages,
          consumedInputBytes: source.length * inspections,
          inputSha256: pdfInspectDescriptor.sha256,
          reportBytes,
          reportSha256: digest.digest('hex'),
          independentPdfLibPages: document.getPageCount(),
          independentPdfJsPages: text.length,
          independentTextVerified: true,
          inputUnchanged: true,
          retainedReportsAfterCompletion: 0,
        };
      } finally {
        reports.length = 0;
      }
    },
  };
}

function texts(pages) {
  return pages.map((page, index) => {
    assert.equal(page.page, index + 1);
    for (const item of page.items)
      for (const name of ['x', 'y', 'width', 'height']) assert.ok(Number.isFinite(item[name]));
    return page.items.map((item) => item.text).join('');
  });
}

export async function verifyPdf(service, fixture) {
  const native = nativePdf(),
    options = { font: 'Helvetica', size: 12, colorHex: '#123456' };
  const builder = service.create();
  builder.addText(fixture.first, 1, 40, 700, options);
  builder.addText(fixture.second, 2, 50, 680, options);
  const bytes = await builder.save();
  assert.ok(bytes instanceof Uint8Array && bytes.byteLength > 100 && bytes.byteLength <= 1048576);
  assert.equal((await native.inspect(bytes)).pages, 2);
  assert.deepEqual(texts(await native.extractText(bytes)), [fixture.first, fixture.second]);
  const nativeBuilder = native.create();
  nativeBuilder.addText(fixture.first, 1, 40, 700, options);
  const input = await PDFDocument.load(await nativeBuilder.save());
  input.setTitle(fixture.title);
  const nativeBytes = await save(input),
    info = await service.inspect(nativeBytes);
  assert.equal(info.pages, 1);
  assert.equal(info.encrypted, false);
  assert.equal(info.signed, false);
  assert.equal(info.title, fixture.title);
  const extracted = await service.extractText(nativeBytes);
  assert.deepEqual(texts(extracted), [fixture.first]);
  const item = extracted[0].items.find((entry) => entry.text === fixture.first);
  assert.ok(item && Math.abs(item.x - 40) < 0.001 && Math.abs(item.y - 700) < 0.001);
  const added = await service.addText(bytes, {
    page: 2,
    text: fixture.added,
    x: 50,
    y: 500,
    ...options,
    rotationDegrees: 15,
  });
  assert.equal((await native.inspect(added)).pages, 2);
  const changed = texts(await native.extractText(added));
  assert.equal(changed[0], fixture.first);
  assert.ok(changed[1].includes(fixture.second) && changed[1].includes(fixture.added));
  const merged = await service.merge([nativeBytes, added]);
  assert.equal((await service.inspect(merged)).pages, 3);
  const actual = texts(await service.extractText(merged)),
    expected = texts(await native.extractText(merged));
  assert.deepEqual(actual, expected);
  assert.equal(actual[0], fixture.first);
  assert.equal(actual[1], fixture.first);
  assert.ok(actual[2].includes(fixture.second) && actual[2].includes(fixture.added));
  return {
    operationsVerified: 5,
    mergedPages: 3,
    nativeToPublicRead: true,
    publicToNativeRead: true,
    metadataVerified: true,
    textGeometryVerified: true,
    rotatedTextRetained: true,
    mergedPageOrderVerified: true,
  };
}
