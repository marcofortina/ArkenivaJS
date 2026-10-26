// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { dataCompressionPlugin } from '../../dist/index.js';
import type { CompressionService, ArchiveEntry, OutputBytes } from '../../dist/index.js';

/** Compile the public single-pass streams and reject unsupported filesystem/protocol inputs. */
export async function publicContract(compression: CompressionService) {
  dataCompressionPlugin({ defaults: {}, policy: { maxConcurrent: 1, timeoutMs: 5000 } });
  const gzip: OutputBytes = compression.gzip(new Uint8Array(), { maxRatio: 1.5 });
  for await (const entry of compression.iterateZip(new Uint8Array())) {
    const typed: ArchiveEntry = entry;
    // @ts-expect-error Extraction targets are never accepted by the iterator.
    compression.iterateZip(new Uint8Array(), { destination: '/tmp/archive' });
    // @ts-expect-error Public entries do not expose filesystem/native handles.
    typed.native();
  }
  // @ts-expect-error Explicit runtime admission and deadline are required.
  dataCompressionPlugin({ defaults: {} });
  // @ts-expect-error ZIP inputs are explicit byte sources rather than path strings.
  compression.createZip([{ path: 'file.txt', data: '/etc/passwd' }]);
  // @ts-expect-error Remote URLs are never fetched implicitly.
  compression.gunzip('https://example.test/archive.gz');
  return gzip;
}
