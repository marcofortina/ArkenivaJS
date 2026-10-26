// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import qrcode from 'qrcode';
import bwip from 'bwip-js';
import sharp from 'sharp';
import zxing from '@zxing/library';
import { KitError } from '@arkenivajs/core';
import type { BarcodeSymbology, CodeOptions, DecodedCode } from './contracts.js';
import { failure } from './settings.js';

export interface Job {
  readonly kind: 'encode' | 'decode';
  readonly input: string | Uint8Array;
  readonly symbology: BarcodeSymbology;
  readonly options: Required<CodeOptions>;
  readonly maxOutputBytes: number;
}
export interface Result {
  readonly output: Uint8Array | readonly DecodedCode[];
  readonly pixels: number;
  readonly bytes: number;
}
const pngSignature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const formats = new Map([
  [zxing.BarcodeFormat.QR_CODE, 'QR' as const],
  [zxing.BarcodeFormat.CODE_128, 'CODE128' as const],
  [zxing.BarcodeFormat.EAN_13, 'EAN13' as const],
]);
function dimensions(width: number | undefined, height: number | undefined, max: number) {
  if (!width || !height || !Number.isSafeInteger(width * height) || width * height > max)
    throw failure('EK_CODE_LIMIT');
  return width * height;
}
function bounded(bytes: Uint8Array, max: number) {
  if (bytes.byteLength > max) throw failure('EK_CODE_LIMIT');
  return bytes;
}
/** Internal native adapter; public callers reach it only through an owned bounded process. */
export async function execute(job: Job): Promise<Result> {
  try {
    if (job.kind === 'encode') {
      const text = job.input as string,
        options = job.options;
      let svg: string;
      if (job.symbology === 'QR') {
        const code = qrcode.create(text, { errorCorrectionLevel: options.errorCorrection });
        if (options.widthPixels < code.modules.size + 8) throw failure('EK_CODE_LIMIT');
        svg = await qrcode.toString(text, {
          type: 'svg',
          width: options.widthPixels,
          margin: 4,
          errorCorrectionLevel: options.errorCorrection,
        });
      } else {
        const render = {
          bcid: job.symbology === 'EAN13' ? 'ean13' : 'code128',
          text,
          height: 20,
          paddingwidth: 10,
          paddingheight: 10,
          includetext: false,
        };
        const base = bwip.toSVG({ ...render, scale: 1 }),
          size = await sharp(Buffer.from(base), { limitInputPixels: false }).metadata();
        dimensions(size.width, size.height, options.maxPixels);
        const scale = Math.floor(options.widthPixels / size.width!);
        if (scale < 1) throw failure('EK_CODE_LIMIT');
        svg = bwip.toSVG({ ...render, scale });
      }
      const source = bounded(Buffer.from(svg, 'utf8'), job.maxOutputBytes),
        size = await sharp(source, { limitInputPixels: false }).metadata(),
        pixels = dimensions(size.width, size.height, options.maxPixels);
      if (size.width! > options.widthPixels) throw failure('EK_CODE_LIMIT');
      const output =
        options.format === 'svg'
          ? source
          : bounded(
              await sharp(source, { limitInputPixels: options.maxPixels }).png().toBuffer(),
              job.maxOutputBytes,
            );
      return { output, pixels, bytes: output.byteLength };
    }
    const source = Buffer.from(job.input as Uint8Array),
      isPng = source.subarray(0, 8).equals(pngSignature),
      isJpeg = source[0] === 0xff && source[1] === 0xd8 && source[2] === 0xff;
    if (!isPng && !isJpeg) throw failure('EK_CODE_UNSUPPORTED');
    // Header-only metadata inspection precedes raster allocation; dimensions gate the decoder.
    const size = await sharp(source, {
      limitInputPixels: false,
      failOn: 'error',
      animated: false,
    }).metadata();
    if (
      (size.format !== 'png' && size.format !== 'jpeg') ||
      (size.pages !== undefined && size.pages > 1)
    )
      throw failure('EK_CODE_UNSUPPORTED');
    const pixels = dimensions(size.width, size.height, job.options.maxPixels),
      image = sharp(source, {
        limitInputPixels: job.options.maxPixels,
        failOn: 'error',
        animated: false,
      }),
      { data, info } = await image
        .flatten({ background: 'white' })
        .greyscale()
        .raw({ depth: 'uchar' })
        .toBuffer({ resolveWithObject: true });
    if (info.channels !== 1 || data.byteLength !== pixels) throw failure('EK_CODE_DECODE');
    const reader = new zxing.MultiFormatReader();
    reader.setHints(new Map([[zxing.DecodeHintType.POSSIBLE_FORMATS, [...formats.keys()]]]));
    try {
      const decoded = reader.decode(
          new zxing.BinaryBitmap(
            new zxing.HybridBinarizer(
              new zxing.RGBLuminanceSource(new Uint8ClampedArray(data), info.width, info.height),
            ),
          ),
        ),
        symbology = formats.get(decoded.getBarcodeFormat()),
        text = decoded.getText(),
        bytes = Buffer.byteLength(text, 'utf8');
      if (!symbology) throw failure('EK_CODE_UNSUPPORTED');
      if (bytes > job.maxOutputBytes) throw failure('EK_CODE_LIMIT');
      return { output: [{ text, symbology }], pixels, bytes };
    } catch (cause) {
      if (cause instanceof zxing.NotFoundException) return { output: [], pixels, bytes: 0 };
      throw cause;
    } finally {
      reader.reset();
    }
  } catch (cause) {
    if (cause instanceof KitError) throw cause;
    // Native messages may contain input values or binary details and never cross the boundary.
    throw failure('EK_CODE_DECODE');
  }
}
