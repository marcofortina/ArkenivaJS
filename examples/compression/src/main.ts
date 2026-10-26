// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { createApplication } from '@arkenivajs/core';
import { COMPRESSION_CAPABILITY, dataCompressionPlugin } from '@arkenivajs/data-compression';
import type { CompressionService, OutputBytes } from '@arkenivajs/data-compression';

/** Collect only this small, explicitly bounded guide fixture. */
async function collect(stream: OutputBytes) {
  const parts: Buffer[] = [];
  let length = 0;
  for await (const chunk of stream) {
    length += chunk.byteLength;
    if (length > 1048576) throw new Error('The example fixture exceeded its byte budget');
    parts.push(Buffer.from(chunk));
  }
  return Buffer.concat(parts);
}
/** Exercise real native GZIP and verified ZIP without filesystem extraction or remote input. */
export async function runCompressionExample() {
  const app = await createApplication({
    service: { name: 'compression-example', version: '0.1.0', environment: 'test' },
    plugins: [
      dataCompressionPlugin({
        defaults: {
          maxCompressedBytes: 1048576,
          maxUncompressedBytes: 1048576,
          maxEntryBytes: 65536,
          maxEntries: 8,
        },
        policy: { maxConcurrent: 1, timeoutMs: 5000 },
      }),
    ],
  });
  try {
    await app.start();
    const compression = app.resolve<CompressionService>(COMPRESSION_CAPABILITY),
      bytes = Buffer.from('Caffè 🦊 東京'),
      compressed = await collect(compression.gzip(bytes)),
      restored = await collect(compression.gunzip(compressed)),
      archive = await collect(
        compression.createZip([
          { path: 'docs/message.txt', data: bytes },
          { path: 'empty.txt', data: new Uint8Array() },
        ]),
      );
    let zipEntries = 0,
      matching = 0;
    for await (const entry of compression.iterateZip(archive)) {
      const data = await collect(entry.data);
      zipEntries++;
      if (
        (entry.path === 'docs/message.txt' && data.equals(bytes)) ||
        (entry.path === 'empty.txt' && data.byteLength === 0)
      )
        matching++;
    }
    return Object.freeze({
      gzipRoundtrip: restored.equals(bytes),
      zipEntries,
      verifiedContents: matching === 2,
    });
  } finally {
    await app.stop();
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  console.log(JSON.stringify(await runCompressionExample()));
