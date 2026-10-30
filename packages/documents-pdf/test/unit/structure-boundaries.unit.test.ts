// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import test from 'node:test';
import { PDFDocument, PDFName, PDFRef, PDFArray, PDFNumber, PDFString } from 'pdf-lib';
import { KitError } from '@arkenivajs/core';
import { perform } from '../../dist/backend.js';
import type { Work } from '../../dist/backend.js';
import type { PdfInfo } from '../../dist/contracts.js';
import { limits } from '../../dist/settings.js';

function work(input: Uint8Array, operation: Work['operation'] = 'inspect'): Work {
  return { operation, limits: limits(), maximum: 1048576, inputs: [input], specs: [], fonts: {} };
}
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;

test('Native PDF graph recognizes signature fields, document timestamps and byte ranges through indirect objects', async () => {
  for (const shape of ['field', 'timestamp', 'range', 'indirect']) {
    const document = await PDFDocument.create();
    document.addPage();
    const context = document.context;
    const dictionary =
      shape === 'field'
        ? context.obj({ FT: 'Sig' })
        : shape === 'timestamp'
          ? context.obj({ Type: 'DocTimeStamp' })
          : shape === 'range'
            ? context.obj({ ByteRange: [0, 1, 2, 3], Contents: PDFString.of('synthetic') })
            : context.obj({ Type: context.register(PDFName.of('Sig')) });
    document.catalog.set(PDFName.of('Owned'), context.register(dictionary));
    const bytes = await document.save();
    assert.equal(((await perform(work(bytes))) as PdfInfo).signed, true, shape);
    for (const operation of ['merge', 'add'] as const)
      await assert.rejects(perform(work(bytes, operation)), code('EK_PDF_SIGNED'), shape);
  }
});
test('Native PDF graph refuses active action families and embedded content before either rewriting operation', async () => {
  const cases = [
    ...[
      'JavaScript',
      'Launch',
      'SubmitForm',
      'ImportData',
      'GoToR',
      'Rendition',
      'RichMediaExecute',
    ].map((kind) => ['S', kind]),
    ...['JS', 'JavaScript', 'OpenAction', 'AA', 'XFA', 'EmbeddedFiles', 'RichMediaContent'].map(
      (key) => [key, 'Owned'],
    ),
  ];
  for (const [key, kind] of cases) {
    const document = await PDFDocument.create();
    document.addPage();
    const dictionary = document.context.obj({});
    dictionary.set(PDFName.of(key!), document.context.register(PDFName.of(kind!)));
    document.catalog.set(PDFName.of('Owned'), document.context.register(dictionary));
    const bytes = await document.save();
    for (const operation of ['merge', 'add'] as const)
      await assert.rejects(perform(work(bytes, operation)), code('EK_PDF_PARSE'), `${key}:${kind}`);
  }
});
test('Native PDF graph bounds deep structures, indirect name chains and large arrays while allowing cycles', async () => {
  for (const shape of ['depth', 'name-chain', 'array', 'escaped-name', 'dangling']) {
    const document = await PDFDocument.create();
    document.addPage();
    const context = document.context,
      root = context.obj({});
    if (shape === 'depth') {
      let current = root;
      for (let depth = 0; depth < 70; depth++) {
        const next = context.obj({});
        current.set(PDFName.of('Next'), next);
        current = next;
      }
    } else if (shape === 'name-chain') {
      let reference = context.register(PDFName.of('Sig'));
      for (let depth = 0; depth < 66; depth++) reference = context.register(reference);
      root.set(PDFName.of('Type'), reference);
    } else if (shape === 'array') {
      root.set(PDFName.of('Items'), PDFArray.withContext(context));
      const array = root.lookup(PDFName.of('Items'), PDFArray);
      for (let index = 0; index < 3000; index++) array.push(PDFNumber.of(index));
    } else if (shape === 'escaped-name') root.set(PDFName.of('Type'), PDFName.of('S#2369g'));
    else root.set(PDFName.of('Missing'), PDFRef.of(99999));
    document.catalog.set(PDFName.of('Owned'), context.register(root));
    const bytes = await document.save();
    const request = work(bytes);
    const bounded =
      shape === 'array'
        ? { ...request, limits: limits({ maxBytes: Math.max(bytes.length, 8192) }) }
        : request;
    await assert.rejects(
      perform(bounded),
      code(['escaped-name', 'dangling'].includes(shape) ? 'EK_PDF_PARSE' : 'EK_PDF_LIMIT'),
      shape,
    );
  }
  const document = await PDFDocument.create();
  document.addPage();
  const dictionary = document.context.obj({}),
    reference = document.context.register(dictionary);
  dictionary.set(PDFName.of('Self'), reference);
  document.catalog.set(PDFName.of('Owned'), reference);
  assert.equal(((await perform(work(await document.save()))) as PdfInfo).pages, 1);
});
test('Native PDF metadata and text budgets reject oversized output without returning partial success', async () => {
  const document = await PDFDocument.create();
  document.addPage();
  document.setTitle('x'.repeat(4097));
  await assert.rejects(perform(work(await document.save())), code('EK_PDF_LIMIT'));
  const request: Work = {
    ...work(new Uint8Array()),
    operation: 'create',
    inputs: [],
    specs: [
      {
        page: 1,
        text: 'first',
        x: 20,
        y: 20,
        font: 'Helvetica',
        size: 12,
        colorHex: '#000000',
        rotationDegrees: 0,
      },
      {
        page: 1,
        text: 'second',
        x: 20,
        y: 100,
        font: 'Helvetica',
        size: 12,
        colorHex: '#000000',
        rotationDegrees: 0,
      },
    ],
  };
  const bytes = (await perform(request)) as Uint8Array;
  await assert.rejects(
    perform({ ...work(bytes, 'extract'), limits: limits({ maxTextItems: 1 }) }),
    code('EK_PDF_LIMIT'),
  );
  await assert.rejects(perform({ ...work(bytes, 'extract'), maximum: 1 }), code('EK_PDF_LIMIT'));
  await assert.rejects(perform({ ...request, maximum: 1 }), code('EK_PDF_LIMIT'));
  await assert.rejects(
    perform({ ...work(bytes, 'merge'), inputs: [bytes, bytes], limits: limits({ maxPages: 1 }) }),
    code('EK_PDF_LIMIT'),
  );
});
