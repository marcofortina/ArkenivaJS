// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import qrcode from 'qrcode';
import bwip from 'bwip-js';
import sharp from 'sharp';
import zxing from '@zxing/library';
import { codesPngFixture, codesPngDescriptor } from './codes-fixture.mjs';

export const codesFixture = Object.freeze({
  qr: 'https://codes.fixture.invalid/verification',
  code128: 'ARK-TEST-128',
  ean13: '4006381333931',
});
export const codesSettings = Object.freeze({
  defaults: Object.freeze({ format: 'png', widthPixels: 512, maxPixels: 262144 }),
  policy: Object.freeze({
    maxConcurrent: 1,
    timeoutMs: 5000,
    maxInputBytes: 65536,
    maxOutputBytes: 65536,
  }),
});
const formats = new Map([
  [zxing.BarcodeFormat.QR_CODE, 'QR'],
  [zxing.BarcodeFormat.CODE_128, 'CODE128'],
  [zxing.BarcodeFormat.EAN_13, 'EAN13'],
]);

/** Direct pinned SDK pipelines for the same fixed valid corpus and rendering parameters. */
export function nativeCodes() {
  const rasterize = async (svg, options) =>
    options.format === 'svg'
      ? Buffer.from(svg)
      : sharp(Buffer.from(svg), { limitInputPixels: 262144 }).png().toBuffer();
  return {
    async generateQr(text, options = {}) {
      return rasterize(
        await qrcode.toString(text, {
          type: 'svg',
          width: options.widthPixels ?? 512,
          margin: 4,
          errorCorrectionLevel: options.errorCorrection ?? 'M',
        }),
        options,
      );
    },
    async generateBarcode(text, symbology, options = {}) {
      const render = {
        bcid: symbology === 'EAN13' ? 'ean13' : 'code128',
        text,
        height: 20,
        paddingwidth: 10,
        paddingheight: 10,
        includetext: false,
      };
      const size = await sharp(Buffer.from(bwip.toSVG({ ...render, scale: 1 }))).metadata();
      return rasterize(
        bwip.toSVG({ ...render, scale: Math.floor((options.widthPixels ?? 512) / size.width) }),
        options,
      );
    },
    async decode(input) {
      const { data, info } = await sharp(input, { limitInputPixels: 262144 })
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

export const codesOperations = Object.freeze([
  'qr-png-encode',
  'code128-png-encode',
  'ean13-png-encode',
  'fixed-qr-png-decode',
]);

/** Retain a finite private output corpus for independent verification after measured callbacks. */
export function codesWorkload(service, fixture = codesFixture) {
  const retained = new Map(codesOperations.slice(0, 3).map((name) => [name, []])),
    input = codesPngFixture(),
    before = Buffer.from(input);
  let retainedBytes = 0,
    decodeCalls = 0,
    completed = false;
  const capture = async (operation, action) => {
    assert.equal(completed, false);
    const outputs = retained.get(operation);
    assert.ok(outputs.length < 120, 'The private barcode output capacity is exceeded');
    const output = await action();
    assert.ok(output instanceof Uint8Array && output.byteLength > 8 && output.byteLength <= 65536);
    assert.ok(retainedBytes + output.byteLength <= 8388608);
    retainedBytes += output.byteLength;
    outputs.push(output);
    return output.byteLength;
  };
  return {
    workload: {
      'qr-png-encode': () =>
        capture('qr-png-encode', () =>
          service.generateQr(fixture.qr, {
            format: 'png',
            widthPixels: 256,
            errorCorrection: 'M',
          }),
        ),
      'code128-png-encode': () =>
        capture('code128-png-encode', () =>
          service.generateBarcode(fixture.code128, 'CODE128', { format: 'png', widthPixels: 512 }),
        ),
      'ean13-png-encode': () =>
        capture('ean13-png-encode', () =>
          service.generateBarcode(fixture.ean13, 'EAN13', { format: 'png', widthPixels: 512 }),
        ),
      async 'fixed-qr-png-decode'() {
        assert.equal(completed, false);
        assert.ok(decodeCalls < 120, 'The fixed barcode decode capacity is exceeded');
        const result = await service.decode(input, { maxPixels: 262144 });
        assert.deepEqual(result, [{ text: fixture.qr, symbology: 'QR' }]);
        decodeCalls++;
        return result.length;
      },
    },
    async complete(records) {
      assert.equal(completed, false);
      completed = true;
      try {
        assert.equal(records.length, codesOperations.length);
        assert.deepEqual(
          records.map((record) => record.operation),
          codesOperations,
        );
        assert.deepEqual(input, before);
        const summaries = [],
          independent = nativeCodes();
        for (const [index, [operation, outputs]] of [...retained.entries()].entries()) {
          const record = records[index],
            count = record.sampleCount + record.warmupIterations,
            symbology = ['QR', 'CODE128', 'EAN13'][index],
            text = [fixture.qr, fixture.code128, fixture.ean13][index],
            digest = createHash('sha256');
          assert.ok(Number.isSafeInteger(count) && count > 0 && count <= 120);
          assert.equal(outputs.length, count);
          let bytes = 0,
            pixels = 0,
            width,
            height;
          for (const output of outputs) {
            const image = Buffer.from(output),
              metadata = await sharp(image, { limitInputPixels: 262144 }).metadata();
            assert.equal(metadata.format, 'png');
            assert.ok(metadata.width > 0 && metadata.width <= (index === 0 ? 256 : 512));
            assert.ok(metadata.height > 0 && metadata.width * metadata.height <= 262144);
            if (width === undefined) {
              width = metadata.width;
              height = metadata.height;
            }
            assert.equal(metadata.width, width);
            assert.equal(metadata.height, height);
            assert.deepEqual(await independent.decode(image), [{ text, symbology }]);
            bytes += image.length;
            pixels += metadata.width * metadata.height;
            digest.update(image);
          }
          summaries.push({
            operation,
            actualCallbacks: count,
            bytes,
            pixels,
            width,
            height,
            sha256: digest.digest('hex'),
          });
        }
        const decodeRecord = records[3];
        assert.equal(decodeCalls, decodeRecord.sampleCount + decodeRecord.warmupIterations);
        assert.deepEqual(await independent.decode(input), [{ text: fixture.qr, symbology: 'QR' }]);
        summaries.push({
          operation: codesOperations[3],
          actualCallbacks: decodeCalls,
          inputBytes: decodeCalls * input.length,
          pixels: decodeCalls * codesPngDescriptor.width * codesPngDescriptor.height,
          inputSha256: codesPngDescriptor.sha256,
        });
        return {
          independentlyVerified: true,
          summaries,
          retainedOutputBytes: retainedBytes,
          retainedOutputsAfterCompletion: 0,
          fixedDecodeInputUnchanged: true,
        };
      } finally {
        for (const outputs of retained.values()) outputs.length = 0;
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
