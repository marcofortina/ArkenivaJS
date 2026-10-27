// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { documentsPdfPlugin, PDF_CAPABILITY } from '../../dist/index.js';
import type { PdfService, PdfInfo, PdfTextPage } from '../../dist/index.js';
/** Public contracts contain typed document values without native PDF engine objects. */
export function contract(pdf: PdfService, info: PdfInfo, page: PdfTextPage) {
  documentsPdfPlugin({
    defaults: {},
    fontAllowlist: ['Helvetica'],
    policy: { maxConcurrent: 1, timeoutMs: 1000 },
  });
  const builder = pdf.create();
  builder.addText('Report', 1, 40, 40, { font: 'Helvetica', size: 12, colorHex: '#000000' });
  // @ts-expect-error No implicit URL fetching is exposed.
  pdf.inspect('https://example.invalid/document.pdf');
  // @ts-expect-error Password bypasses are not part of the document policy.
  pdf.inspect(new Uint8Array(), { password: 'invalid' });
  // @ts-expect-error Fonts must be explicit deployment configuration.
  documentsPdfPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 1000 } });
  // @ts-expect-error Document metadata is readonly.
  info.signed = false;
  // @ts-expect-error Text items are readonly.
  page.items.push({ text: 'Invalid', x: 0, y: 0, width: 0, height: 0 });
  return PDF_CAPABILITY;
}
