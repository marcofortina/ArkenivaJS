// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { crc32 } from 'node:zlib';
import sharp from 'sharp';
import qrcode from 'qrcode';
import bwip from 'bwip-js';
import { createApplication, KitError } from '@arkenivajs/core';
import { CODES_CAPABILITY, dataCodesPlugin } from '../../dist/index.js';
import { execute } from '../../dist/codec.js';
import type { CodeService, DataCodesPluginSettings, BarcodeSymbology } from '../../dist/index.js';

const settings = (): DataCodesPluginSettings => ({
  defaults: {},
  policy: { maxConcurrent: 1, timeoutMs: 5000 },
});
const code = (expected: string) => (error: unknown) =>
  error instanceof KitError && error.code === expected;
async function fixture(config = settings()) {
  const app = await createApplication({
    service: { name: 'codes-tests', version: '0.1.0', environment: 'test' },
    plugins: [dataCodesPlugin(config)],
  });
  await app.start();
  return { app, codes: app.resolve<CodeService>(CODES_CAPABILITY) };
}
test('All three native symbologies roundtrip PNG and QR preserves unusual Unicode', async () => {
  const { app, codes } = await fixture();
  try {
    for (const [symbology, text] of [
      ['QR', 'Caffè 🦊 東京 e\u0301\nhttps://untrusted.invalid/private'],
      ['CODE128', 'ARKENIVA-123'],
      ['EAN13', '5901234123457'],
    ] as const) {
      const png = await codes.generateBarcode(text, symbology),
        metadata = await sharp(png).metadata(),
        result = await codes.decode(png);
      assert.equal(metadata.format, 'png');
      assert.ok(metadata.width! <= 512);
      assert.ok(metadata.width! * metadata.height! <= 4194304);
      assert.deepEqual(result, [{ text, symbology }]);
      assert.ok(Object.isFrozen(result) && Object.isFrozen(result[0]));
      assert.ok(!Object.hasOwn(result[0]!, 'confidence'));
    }
  } finally {
    await app.stop();
  }
});
test('SVG output is native UTF-8, has bounded geometry and rasterizes to a decodable carrier', async () => {
  const { app, codes } = await fixture();
  try {
    for (const symbology of ['QR', 'CODE128', 'EAN13'] as const) {
      const text = symbology === 'EAN13' ? '5901234123457' : 'SVG<&fixture>',
        svg = await codes.generateBarcode(text, symbology, { format: 'svg', widthPixels: 512 }),
        string = Buffer.from(svg).toString('utf8');
      assert.match(string, /<svg\b/);
      assert.ok(!string.includes('SVG<&fixture>'));
      const raster = await sharp(svg).png().toBuffer();
      assert.deepEqual(await codes.decode(raster), [{ text, symbology }]);
    }
    const qr = await codes.generateQr('dimensions', { widthPixels: 256, errorCorrection: 'H' });
    assert.equal((await sharp(qr).metadata()).width, 256);
  } finally {
    await app.stop();
  }
});
test('Independent upstream PNG and JPEG fixtures decode without using framework generation', async () => {
  const { app, codes } = await fixture();
  try {
    for (const [symbology, text] of [
      ['QR', 'independent Ω'],
      ['CODE128', 'EXTERNAL-42'],
      ['EAN13', '4006381333931'],
    ] as const) {
      const png =
        symbology === 'QR'
          ? await qrcode.toBuffer(text, { width: 512 })
          : await bwip.toBuffer({
              bcid: symbology === 'EAN13' ? 'ean13' : 'code128',
              text,
              scale: 3,
              height: 20,
              paddingwidth: 10,
              paddingheight: 10,
            });
      for (const image of [
        png,
        await sharp(png).flatten({ background: 'white' }).jpeg({ quality: 95 }).toBuffer(),
      ])
        assert.deepEqual(await codes.decode(image), [{ text, symbology }]);
    }
  } finally {
    await app.stop();
  }
});
test('Native EAN13 check digit validation and input envelopes fail without disclosing payloads', async () => {
  const { app, codes } = await fixture();
  try {
    await assert.rejects(codes.generateBarcode('5901234123458', 'EAN13'), code('EK_CODE_DECODE'));
    for (const value of ['', null, {}, '\ud800'])
      await assert.rejects(codes.generateQr(value as never), code('EK_CODE_DECODE'));
    await assert.rejects(codes.generateBarcode('é', 'CODE128'), code('EK_CODE_DECODE'));
    await assert.rejects(codes.generateBarcode('123', 'EAN13'), code('EK_CODE_DECODE'));
    await assert.rejects(
      codes.generateBarcode('123', 'EAN8' as BarcodeSymbology),
      code('EK_CODE_UNSUPPORTED'),
    );
    await assert.rejects(codes.generateQr('x'.repeat(2954)), code('EK_CODE_LIMIT'));
    await assert.rejects(codes.generateBarcode('x'.repeat(257), 'CODE128'), code('EK_CODE_LIMIT'));
    await assert.rejects(
      codes.generateQr('x'.repeat(100), { widthPixels: 32 }),
      code('EK_CODE_LIMIT'),
    );
    await assert.rejects(
      codes.generateBarcode('EXCESSIVE-WIDTH', 'CODE128', { widthPixels: 32 }),
      code('EK_CODE_LIMIT'),
    );
  } finally {
    await app.stop();
  }
});
test('No-symbol images, corrupt raster data and unsupported formats have distinct safe outcomes', async () => {
  const { app, codes } = await fixture();
  try {
    const blank = await sharp({
      create: { width: 64, height: 64, channels: 3, background: 'white' },
    })
      .png()
      .toBuffer();
    assert.deepEqual(await codes.decode(blank), []);
    for (const bytes of [
      Buffer.from('<svg><script>private-payload</script></svg>'),
      Buffer.from('https://private.invalid/a'),
      Buffer.from('GIF89a'),
    ])
      await assert.rejects(codes.decode(bytes), code('EK_CODE_UNSUPPORTED'));
    const png = await codes.generateQr('private-payload');
    await assert.rejects(codes.decode(png.subarray(0, 40)), (error) => {
      assert.ok(code('EK_CODE_DECODE')(error));
      assert.ok(!JSON.stringify((error as KitError).toSafeJSON()).includes('private-payload'));
      return true;
    });
  } finally {
    await app.stop();
  }
});
test('Input/output bytes and pixel limits reject before unbounded raster allocation', async () => {
  const { app, codes } = await fixture();
  try {
    const png = await qrcode.toBuffer('bounded image', { width: 512 });
    const bomb = Buffer.from(png);
    bomb.writeUInt32BE(65535, 16);
    bomb.writeUInt32BE(65535, 20);
    bomb.writeUInt32BE(crc32(bomb.subarray(12, 29)), 29);
    await assert.rejects(codes.decode(bomb), code('EK_CODE_LIMIT'));
    await assert.rejects(codes.decode(png, { maxPixels: 1024 }), code('EK_CODE_LIMIT'));
    await assert.rejects(
      codes.generateQr('bounded output', { maxPixels: 1024 }),
      code('EK_CODE_LIMIT'),
    );
    await assert.rejects(codes.decode(new Uint8Array(1048577)), code('EK_CODE_LIMIT'));
    await assert.rejects(codes.decode(new Uint8Array()), code('EK_CODE_LIMIT'));
    await assert.rejects(codes.decode({} as never), code('EK_CODE_DECODE'));
  } finally {
    await app.stop();
  }
  const small = await fixture({
    defaults: {},
    policy: { maxConcurrent: 1, timeoutMs: 5000, maxInputBytes: 16, maxOutputBytes: 64 },
  });
  try {
    await assert.rejects(small.codes.generateQr('small'), code('EK_CODE_LIMIT'));
    await assert.rejects(small.codes.generateQr('x'.repeat(17)), code('EK_CODE_LIMIT'));
  } finally {
    await small.app.stop();
  }
});
test('Configuration is captured, strict and never invokes option getters', async () => {
  let reads = 0;
  const getter = Object.defineProperty({}, 'maxPixels', {
    enumerable: true,
    get() {
      reads++;
      return 1;
    },
  });
  for (const config of [
    null,
    {},
    { defaults: {}, policy: { maxConcurrent: 0, timeoutMs: 1000 } },
    { defaults: {}, policy: { maxConcurrent: 5, timeoutMs: 1000 } },
    { defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 0 } },
    { defaults: { format: 'jpeg' }, policy: settings().policy },
    { defaults: getter, policy: settings().policy },
    { defaults: {}, policy: { ...settings().policy, maxInputBytes: 0 } },
  ])
    assert.throws(() => dataCodesPlugin(config as never), code('EK_CONFIG_INVALID'));
  const config = { defaults: { widthPixels: 256 }, policy: { maxConcurrent: 1, timeoutMs: 5000 } },
    plugin = dataCodesPlugin(config);
  config.defaults.widthPixels = 32;
  const app = await createApplication({
    service: { name: 'codes-tests', version: '0.1.0', environment: 'test' },
    plugins: [plugin],
  });
  try {
    await app.start();
    const codes = app.resolve<CodeService>(CODES_CAPABILITY);
    assert.equal((await sharp(await codes.generateQr('captured')).metadata()).width, 256);
    for (const options of [
      null,
      getter,
      { unknown: true },
      { widthPixels: 257 },
      { maxPixels: 4194305 },
      { errorCorrection: 'automatic' },
      { timeoutMs: 0 },
      { signal: { aborted: false } },
    ])
      await assert.rejects(
        codes.decode(new Uint8Array([1]), options as never),
        code('EK_CONFIG_INVALID'),
      );
    assert.equal(reads, 0);
  } finally {
    await app.stop();
  }
});
test('Bounded corrupt-image mutations settle safely and preserve the next valid operation', async () => {
  const { app, codes } = await fixture();
  try {
    const png = await qrcode.toBuffer('mutation fixture', { width: 256 });
    for (let index = 0; index < 16; index++) {
      const bytes = Buffer.from(png.subarray(0, Math.min(png.length, 8 + index * 7)));
      await assert.rejects(
        codes.decode(bytes),
        (error) => code('EK_CODE_DECODE')(error) || code('EK_CODE_LIMIT')(error),
      );
    }
    assert.equal((await codes.decode(png))[0]?.text, 'mutation fixture');
  } finally {
    await app.stop();
  }
});
test('Binary input is snapshotted through native storage without invoking caller hooks', async () => {
  const { app, codes } = await fixture();
  try {
    let reads = 0;
    const image = new Uint8Array(await qrcode.toBuffer('owned image', { width: 256 }));
    Object.defineProperty(image, 'buffer', {
      get() {
        reads++;
        throw new Error('private-buffer-value');
      },
    });
    Object.defineProperty(image, Symbol.iterator, {
      value() {
        reads++;
        throw new Error('private-iterator-value');
      },
    });
    const operation = codes.decode(image);
    image.fill(0);
    assert.equal((await operation)[0]?.text, 'owned image');
    assert.equal(reads, 0);
    await assert.rejects(codes.decode(new Proxy(image, {})), code('EK_CODE_DECODE'));
    const { SharedArrayBuffer } = globalThis;
    await assert.rejects(
      codes.decode(new Uint8Array(new SharedArrayBuffer(8))),
      code('EK_CODE_DECODE'),
    );
    const options = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('private-option-value');
        },
      },
    );
    await assert.rejects(codes.decode(image, options), code('EK_CONFIG_INVALID'));
  } finally {
    await app.stop();
  }
});
test('Physical admission has no queue and cancellation retains its slot until process exit', async () => {
  const { app, codes } = await fixture();
  try {
    const image = await qrcode.toBuffer('cancelled job', { width: 512 }),
      controller = new AbortController(),
      running = codes.decode(image, { signal: controller.signal }),
      cancelled = assert.rejects(running, code('EK_ABORTED'));
    await assert.rejects(codes.decode(image), code('EK_CODE_LIMIT'));
    controller.abort(new Error('private-abort-reason'));
    await cancelled;
    await assert.rejects(codes.decode(image), code('EK_CODE_LIMIT'));
    let recovered = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      await delay(20);
      try {
        assert.equal((await codes.decode(image))[0]?.text, 'cancelled job');
        recovered = true;
        break;
      } catch (error) {
        assert.ok(code('EK_CODE_LIMIT')(error));
      }
    }
    assert.ok(recovered);
    const stopped = new AbortController();
    stopped.abort();
    await assert.rejects(codes.decode(image, { signal: stopped.signal }), code('EK_ABORTED'));
  } finally {
    await app.stop();
  }
});
test('Deadlines terminate native work and reject late acknowledgements', async () => {
  const { app, codes } = await fixture();
  try {
    const image = await qrcode.toBuffer('deadline fixture', { width: 512 }),
      running = codes.decode(image, { timeoutMs: 1 }),
      checked = assert.rejects(running, code('EK_TIMEOUT'));
    // Block only the test owner so both a native response and the timer can become overdue.
    const { SharedArrayBuffer } = globalThis;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15);
    await checked;
  } finally {
    await app.stop();
  }
});
test('Stopping one application terminates active work and leaves another owner usable', async () => {
  const a = await fixture(),
    b = await fixture();
  try {
    const running = a.codes.generateQr('shutdown'),
      rejected = assert.rejects(running, code('EK_RESOURCE_CLOSED'));
    await a.app.stop();
    await rejected;
    await a.app.stop();
    await assert.rejects(a.codes.generateQr('closed'), code('EK_RESOURCE_CLOSED'));
    assert.equal(
      (await b.codes.decode(await b.codes.generateQr('other owner')))[0]?.text,
      'other owner',
    );
  } finally {
    await a.app.stop();
    await b.app.stop();
  }
});
test('Internal adapter exercises the same bounded native algorithms without invented confidence', async () => {
  for (const symbology of ['QR', 'CODE128', 'EAN13'] as const) {
    const input = symbology === 'EAN13' ? '5901234123457' : 'native adapter',
      options = {
        format: 'png' as const,
        widthPixels: 512,
        maxPixels: 4194304,
        errorCorrection: 'M' as const,
      },
      encoded = await execute({
        kind: 'encode',
        input,
        symbology,
        options,
        maxOutputBytes: 8388608,
      }),
      decoded = await execute({
        kind: 'decode',
        input: encoded.output as Uint8Array,
        symbology,
        options,
        maxOutputBytes: 8388608,
      });
    assert.deepEqual(decoded.output, [{ text: input, symbology }]);
    await assert.rejects(
      execute({
        kind: 'decode',
        input: encoded.output as Uint8Array,
        symbology,
        options,
        maxOutputBytes: 1,
      }),
      code('EK_CODE_LIMIT'),
    );
  }
  assert.equal(sharp.versions.sharp, '0.35.5');
});
test('Native adapter rejects malformed carriers and hostile raster dimensions before decoding', async () => {
  const options = {
      format: 'png' as const,
      widthPixels: 512,
      maxPixels: 4194304,
      errorCorrection: 'M' as const,
    },
    encode = {
      kind: 'encode' as const,
      input: 'native boundary',
      symbology: 'QR' as const,
      options,
      maxOutputBytes: 8388608,
    },
    png = await qrcode.toBuffer('native boundary', { width: 256 }),
    decode = {
      kind: 'decode' as const,
      input: png,
      symbology: 'QR' as const,
      options,
      maxOutputBytes: 8388608,
    };
  await assert.rejects(
    execute({ ...encode, options: { ...options, widthPixels: 32 }, input: 'x'.repeat(100) }),
    code('EK_CODE_LIMIT'),
  );
  await assert.rejects(
    execute({ ...encode, options: { ...options, widthPixels: 32 }, symbology: 'CODE128' }),
    code('EK_CODE_LIMIT'),
  );
  await assert.rejects(execute({ ...encode, maxOutputBytes: 1 }), code('EK_CODE_LIMIT'));
  await assert.rejects(
    execute({ ...encode, input: '5901234123458', symbology: 'EAN13' }),
    code('EK_CODE_DECODE'),
  );
  await assert.rejects(
    execute({ ...decode, input: Buffer.from('<svg/>') }),
    code('EK_CODE_UNSUPPORTED'),
  );
  await assert.rejects(execute({ ...decode, input: png.subarray(0, 40) }), code('EK_CODE_DECODE'));
  await assert.rejects(
    execute({ ...decode, options: { ...options, maxPixels: 100 } }),
    code('EK_CODE_LIMIT'),
  );
  assert.deepEqual(
    (await execute({ ...decode, input: await sharp(png).jpeg({ quality: 95 }).toBuffer() })).output,
    [{ text: 'native boundary', symbology: 'QR' }],
  );
  const blank = await sharp({ create: { width: 64, height: 64, channels: 3, background: 'white' } })
    .png()
    .toBuffer();
  assert.deepEqual((await execute({ ...decode, input: blank })).output, []);
  assert.match(
    Buffer.from(
      (await execute({ ...encode, options: { ...options, format: 'svg' } })).output as Uint8Array,
    ).toString('utf8'),
    /<svg/,
  );
});
