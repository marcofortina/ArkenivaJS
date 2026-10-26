// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { CODES_CAPABILITY, dataCodesPlugin } from '@arkenivajs/data-barcodes';
import type { CodeService } from '@arkenivajs/data-barcodes';

/** Generate and detect three real carrier formats without writing files or following links. */
export async function runBarcodesExample() {
  const app = await createApplication({
    service: { name: 'barcodes-example', version: '0.1.0', environment: 'test' },
    plugins: [
      dataCodesPlugin({
        defaults: { widthPixels: 512, maxPixels: 1048576 },
        policy: {
          maxConcurrent: 1,
          timeoutMs: 5000,
          maxInputBytes: 1048576,
          maxOutputBytes: 1048576,
        },
      }),
    ],
  });
  try {
    await app.start();
    const codes = app.resolve<CodeService>(CODES_CAPABILITY);
    let roundtrips = 0;
    for (const [symbology, text] of [
      ['QR', 'Caffè 🦊 東京'],
      ['CODE128', 'ARKENIVA-123'],
      ['EAN13', '5901234123457'],
    ] as const) {
      const image = await codes.generateBarcode(text, symbology),
        result = await codes.decode(image);
      if (result.length === 1 && result[0]!.text === text && result[0]!.symbology === symbology)
        roundtrips++;
    }
    const svg = await codes.generateQr('public SVG fixture', { format: 'svg' });
    return Object.freeze({
      roundtrips,
      svgGenerated: Buffer.from(svg).toString('utf8').includes('<svg'),
    });
  } finally {
    await app.stop();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await runBarcodesExample()));
