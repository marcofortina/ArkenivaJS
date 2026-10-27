// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { documentsPdfPlugin, PDF_CAPABILITY } from '@arkenivajs/documents-pdf';
import type { PdfService } from '@arkenivajs/documents-pdf';

/** Exercise native searchable PDF composition without persistence or remote resources. */
export async function runPdfExample() {
  const app = await createApplication({
    service: { name: 'pdf-example', version: '0.1.0', environment: 'test' },
    plugins: [
      documentsPdfPlugin({
        defaults: { maxBytes: 1048576, maxPages: 10, maxTextItems: 1000, maxDecodeMs: 10000 },
        fontAllowlist: ['Helvetica'],
        policy: { maxConcurrent: 1, timeoutMs: 10000 },
      }),
    ],
  });
  try {
    await app.start();
    const pdf = app.resolve<PdfService>(PDF_CAPABILITY),
      builder = pdf.create();
    builder.addText('ArkenivaJS report', 1, 40, 790, {
      font: 'Helvetica',
      size: 18,
      colorHex: '#112233',
    });
    builder.addText('Protocol 12345/2026', 1, 40, 750, {
      font: 'Helvetica',
      size: 12,
      colorHex: '#000000',
    });
    const original = await builder.save(),
      edited = await pdf.addText(original, {
        page: 1,
        text: 'Reviewed',
        x: 500,
        y: 100,
        font: 'Helvetica',
        size: 12,
        colorHex: '#000000',
        rotationDegrees: 90,
      }),
      combined = await pdf.merge([original, edited]),
      info = await pdf.inspect(combined),
      text = await pdf.extractText(combined);
    return {
      info,
      pages: text.map((page) => ({
        page: page.page,
        text: page.items.map((item) => item.text).join(' '),
      })),
      outputBytes: combined.byteLength,
    };
  } finally {
    await app.stop();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await runPdfExample()));
