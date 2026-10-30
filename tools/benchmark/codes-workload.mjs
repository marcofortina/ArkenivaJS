// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import qrcode from 'qrcode';
import bwip from 'bwip-js';
import sharp from 'sharp';
import zxing from '@zxing/library';

export const codesFixture = Object.freeze({
  qr: 'https://codes.fixture.invalid/verification',
  code128: 'ARK-TEST-128',
  ean13: '4006381333931',
});
export const codesSettings = Object.freeze({
  defaults: Object.freeze({ format: 'png', widthPixels: 512 }),
  policy: Object.freeze({ maxConcurrent: 1, timeoutMs: 5000 }),
});
const formats = new Map([
  [zxing.BarcodeFormat.QR_CODE, 'QR'],
  [zxing.BarcodeFormat.CODE_128, 'CODE128'],
  [zxing.BarcodeFormat.EAN_13, 'EAN13'],
]);

/** Bare SDK image operations are used only for fixed valid functional fixtures. */
export function nativeCodes() {
  return {
    generateQr(text, options = {}) {
      return options.format === 'svg'
        ? qrcode
            .toString(text, { type: 'svg', width: 256, margin: 4, errorCorrectionLevel: 'M' })
            .then((value) => Buffer.from(value))
        : qrcode.toBuffer(text, { type: 'png', width: 256, margin: 4, errorCorrectionLevel: 'M' });
    },
    generateBarcode(text, symbology) {
      return bwip.toBuffer({
        bcid: symbology === 'EAN13' ? 'ean13' : 'code128',
        text,
        height: 20,
        scale: 2,
        paddingwidth: 10,
        paddingheight: 10,
        includetext: false,
      });
    },
    async decode(input) {
      const { data, info } = await sharp(input)
        .flatten({ background: 'white' })
        .greyscale()
        .raw({ depth: 'uchar' })
        .toBuffer({ resolveWithObject: true });
      const reader = new zxing.MultiFormatReader();
      reader.setHints(new Map([[zxing.DecodeHintType.POSSIBLE_FORMATS, [...formats.keys()]]]));
      try {
        const result = reader.decode(
          new zxing.BinaryBitmap(
            new zxing.HybridBinarizer(
              new zxing.RGBLuminanceSource(new Uint8ClampedArray(data), info.width, info.height),
            ),
          ),
        );
        return [{ text: result.getText(), symbology: formats.get(result.getBarcodeFormat()) }];
      } finally {
        reader.reset();
      }
    },
  };
}

export async function verifyCodes(service, fixture = codesFixture) {
  for (const [symbology, text] of [
    ['QR', fixture.qr],
    ['CODE128', fixture.code128],
    ['EAN13', fixture.ean13],
  ]) {
    const image =
      symbology === 'QR'
        ? await service.generateQr(text, { format: 'png', widthPixels: 256 })
        : await service.generateBarcode(text, symbology, { format: 'png', widthPixels: 512 });
    assert.ok(image instanceof Uint8Array && image.byteLength > 8);
    assert.deepEqual([...image.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
    assert.deepEqual(await service.decode(image), [{ text, symbology }]);
  }
  const svg = await service.generateQr(fixture.qr, { format: 'svg', widthPixels: 256 });
  const text = Buffer.from(svg).toString('utf8');
  assert.ok(text.startsWith('<svg') && text.includes('</svg>'));
  return { checkedPngRoundtrips: 3, checkedSvgOutputs: 1, actualNativeDecoding: true };
}
