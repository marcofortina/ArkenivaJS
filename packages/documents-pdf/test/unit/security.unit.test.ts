// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { Readable } from 'node:stream';
import { mkdtemp, writeFile, chmod, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PDFDocument } from 'pdf-lib';
import { KitError } from '@arkenivajs/core';
import { capture, spec, limits } from '../../dist/settings.js';
import { managedService } from '../../dist/service.js';
import type { DocumentsPdfPluginSettings, PdfTextSpec } from '../../dist/index.js';

const config = (): DocumentsPdfPluginSettings => ({
  defaults: {},
  fontAllowlist: ['Helvetica'],
  policy: { maxConcurrent: 1, timeoutMs: 10000 },
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
function fixture(settings = config()) {
  const controller = new AbortController();
  return { ...managedService(capture(settings), controller.signal, () => true), controller };
}

test('Real AES-encrypted native PDF fixtures are rejected without accepting a password bypass', async () => {
  const require = createRequire(import.meta.url),
    Native = require('pdfkit') as new (
      options: object,
    ) => Readable & { text(value: string): unknown; end(): void };
  const document = new Native({
      pdfVersion: '1.7ext3',
      userPassword: 'public-fixture-reader',
      ownerPassword: 'public-fixture-owner',
    }),
    chunks: Buffer[] = [];
  const reading = (async () => {
    for await (const chunk of document) chunks.push(Buffer.from(chunk as Uint8Array));
  })();
  document.text('Synthetic encrypted document');
  document.end();
  await reading;
  const bytes = Buffer.concat(chunks),
    f = fixture();
  try {
    assert.ok(bytes.includes(Buffer.from('/Encrypt')));
    for (const operation of [
      () => f.service.inspect(bytes),
      () => f.service.extractText(bytes),
      () => f.service.merge([bytes]),
      () =>
        f.service.addText(bytes, {
          page: 1,
          text: 'Denied',
          x: 0,
          y: 0,
          font: 'Helvetica',
          size: 12,
          colorHex: '#000000',
        }),
    ])
      await assert.rejects(operation, code('EK_PDF_PARSE'));
    const native = (await import(import.meta.resolve('pdfjs-dist/legacy/build/pdf.mjs'))) as {
      getDocument(options: object): {
        promise: Promise<{ numPages: number }>;
        destroy(): Promise<void>;
      };
    };
    const task = native.getDocument({
      data: new Uint8Array(bytes),
      password: 'public-fixture-reader',
      verbosity: 0,
      useWasm: false,
    });
    try {
      assert.equal((await task.promise).numPages, 1);
    } finally {
      await task.destroy();
    }
  } finally {
    await f.close();
  }
});
test('Hostile settings, accessors, unknown fields, unapproved fonts and malformed operation controls fail before parsing', async () => {
  for (const settings of [
    undefined,
    {},
    { ...config(), fontAllowlist: [] },
    { ...config(), fontAllowlist: ['http://127.0.0.1/font.ttf'] },
    { ...config(), policy: { maxConcurrent: 0, timeoutMs: 1 } },
    { ...config(), defaults: { maxDecodeMs: Infinity } },
  ])
    assert.throws(() => capture(settings as DocumentsPdfPluginSettings), code('EK_CONFIG_INVALID'));
  const settings = capture(config()),
    policy = limits();
  for (const text of [
    { page: 1, text: 'x', x: NaN, y: 0, font: 'Helvetica', size: 12, colorHex: '#000000' },
    { page: 1, text: 'x', x: 0, y: 0, font: 'Denied', size: 12, colorHex: '#000000' },
    { page: 1, text: 'x', x: 0, y: 0, font: 'Helvetica', size: 12, colorHex: 'red' },
    {
      page: 1,
      text: 'x',
      x: 0,
      y: 0,
      font: 'Helvetica',
      size: 12,
      colorHex: '#000000',
      arbitrary: true,
    },
    Object.defineProperty({}, 'text', {
      enumerable: true,
      get() {
        throw new Error('Accessor must not execute');
      },
    }),
  ])
    assert.throws(() => spec(text as PdfTextSpec, settings, policy));
  const f = fixture();
  try {
    await assert.rejects(
      f.service.inspect(Buffer.from('invalid'), { signal: { aborted: false } as AbortSignal }),
    );
    await assert.rejects(f.service.inspect(new Uint8Array(new SharedArrayBuffer(10))));
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      f.service.inspect(Buffer.from('invalid'), { signal: controller.signal }),
      code('EK_ABORTED'),
    );
  } finally {
    await f.close();
  }
});
test('Admission is finite, concurrent saves do not queue, and caller cancellation joins the actual native child', async () => {
  const f = fixture();
  try {
    const builder = f.service.create();
    builder.addText('Owned', 1, 40, 40, { font: 'Helvetica', size: 12, colorHex: '#000000' });
    const saving = builder.save();
    await assert.rejects(builder.save(), code('EK_PDF_LIMIT'));
    await assert.rejects(f.service.inspect(Buffer.from('denied')), code('EK_PDF_LIMIT'));
    const bytes = await saving;
    await assert.rejects(f.service.inspect(bytes, { timeoutMs: 1 }), code('EK_TIMEOUT'));
    await f.close();
  } finally {
    await f.close();
  }
  const other = fixture();
  try {
    const document = await PDFDocument.create();
    document.addPage();
    const bytes = new Uint8Array(await document.save()),
      controller = new AbortController();
    const reading = other.service.inspect(bytes, { signal: controller.signal });
    controller.abort();
    await assert.rejects(reading, code('EK_ABORTED'));
    await other.close();
    assert.ok(bytes.some((value) => value !== 0));
  } finally {
    await other.close();
  }
});
test('Custom font files require approved bounded regular files with safe permissions and no leaf symlinks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'arkenivajs-pdf-bad-font-')),
    file = join(root, 'font.ttf'),
    link = join(root, 'link.ttf');
  await writeFile(file, Buffer.from('malformed font'), { mode: 0o600 });
  await symlink(file, link);
  try {
    for (const selected of [link, file]) {
      const f = fixture({ ...config(), fontAllowlist: [selected] });
      try {
        const builder = f.service.create();
        builder.addText('x', 1, 0, 0, { font: selected, size: 12, colorHex: '#000000' });
        await assert.rejects(builder.save(), code('EK_PDF_PARSE'));
      } finally {
        await f.close();
      }
    }
    await chmod(file, 0o666);
    const f = fixture({ ...config(), fontAllowlist: [file] });
    try {
      const builder = f.service.create();
      builder.addText('x', 1, 0, 0, { font: file, size: 12, colorHex: '#000000' });
      await assert.rejects(builder.save());
    } finally {
      await f.close();
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
test('Output ceilings and closed readiness never produce a successful partial PDF', async () => {
  const f = fixture({
    ...config(),
    policy: { maxConcurrent: 1, timeoutMs: 10000, maxOutputBytes: 100 },
  });
  try {
    await assert.rejects(f.service.create().save(), code('EK_PDF_LIMIT'));
  } finally {
    await f.close();
  }
  const managed = managedService(capture(config()), new AbortController().signal, () => false);
  try {
    assert.throws(() => managed.service.create(), code('EK_RESOURCE_CLOSED'));
  } finally {
    await managed.close();
  }
});
test(
  'Compressed object-stream expansion cannot escape the owned native process memory budget',
  { timeout: 30000 },
  async () => {
    const { createDeflate } = await import('node:zlib'),
      { PDFRawStream } = await import('pdf-lib');
    const segment = Buffer.alloc(1024 * 1024, 32),
      chunks: Buffer[] = [];
    const compressed = Readable.from(
      (function* () {
        yield Buffer.from('42 0 null ');
        for (let index = 0; index < 320; index++) yield segment;
      })(),
    ).pipe(createDeflate());
    for await (const chunk of compressed) chunks.push(Buffer.from(chunk as Uint8Array));
    const document = await PDFDocument.create();
    document.addPage();
    document.context.register(
      PDFRawStream.of(
        document.context.obj({ Type: 'ObjStm', N: 1, First: 5, Filter: 'FlateDecode' }),
        Buffer.concat(chunks),
      ),
    );
    const input = new Uint8Array(await document.save({ useObjectStreams: false })),
      f = fixture({ ...config(), defaults: { maxBytes: 1048576, maxDecodeMs: 10000 } });
    try {
      assert.ok(input.length < 1048576);
      const small = await PDFDocument.create();
      small.addPage();
      small.context.register(
        small.context.flateStream(Buffer.from('42 0 null '), { Type: 'ObjStm', N: 1, First: 5 }),
      );
      const supported = new Uint8Array(await small.save({ useObjectStreams: false }));
      assert.equal((await f.service.inspect(supported)).pages, 1);
      // The kernel can refuse allocation before sampled RSS crosses its threshold; native parsers sanitize that refusal as a parse failure.
      await assert.rejects(
        f.service.inspect(input),
        (error) =>
          error instanceof KitError && ['EK_PDF_LIMIT', 'EK_PDF_PARSE'].includes(error.code),
      );
      await f.close();
      const recovered = fixture({
        ...config(),
        defaults: { maxBytes: 1048576, maxDecodeMs: 10000 },
      });
      try {
        assert.equal((await recovered.service.inspect(supported)).pages, 1);
      } finally {
        await recovered.close();
      }
    } finally {
      await f.close();
      segment.fill(0);
    }
  },
);
