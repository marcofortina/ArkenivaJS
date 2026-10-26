// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataCodesPlugin } from '../../dist/index.js';
import type { CodeService, DecodedCode } from '../../dist/index.js';

/** Compile the public carrier contract without starting processes or evaluating fixtures. */
export async function publicContract(codes: CodeService) {
  dataCodesPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 1000 } });
  const png: Uint8Array = await codes.generateQr('public fixture', { format: 'png' });
  const result: readonly DecodedCode[] = await codes.decode(png, {
    signal: new AbortController().signal,
  });
  // @ts-expect-error Runtime process admission and deadline are required.
  dataCodesPlugin({ defaults: {} });
  // @ts-expect-error Other 1D symbologies are not enabled implicitly.
  await codes.generateBarcode('123', 'EAN8');
  // @ts-expect-error Decode accepts binary images rather than paths, URLs or SVG text.
  await codes.decode('https://example.test/image.png');
  // @ts-expect-error Pixel width is the public typed field.
  await codes.generateQr('public fixture', { sizePixels: 512 });
  // @ts-expect-error Returned carriers are readonly.
  result.push({ text: 'manual', symbology: 'QR' });
  return result;
}
