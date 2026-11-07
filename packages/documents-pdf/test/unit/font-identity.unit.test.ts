// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import type { Stats, BigIntStats } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError, createApplication } from '@arkenivajs/core';
import { documentsPdfPlugin, PDF_CAPABILITY } from '../../dist/index.js';
import type { PdfService } from '../../dist/index.js';

function wideMetadata<T extends Stats | BigIntStats>(value: T, inode: bigint): T {
  const bigint = typeof value.ino === 'bigint',
    device = 1n << 54n;
  return Object.assign(value, {
    dev: bigint ? device : Number(device),
    ino: bigint ? inode : Number(inode),
  });
}

async function verifyFont(context: TestContext, wide: boolean, replace: boolean): Promise<void> {
  const require = createRequire(import.meta.url),
    source = require.resolve('@fontsource/noto-sans/files/noto-sans-greek-400-normal.woff'),
    directory = await fs.mkdtemp(join(tmpdir(), 'arkenivajs-pdf-font-identity-')),
    selected = join(directory, 'selected.woff'),
    replacement = join(directory, 'replacement.woff');
  await fs.copyFile(source, selected);
  await fs.copyFile(source, replacement);
  await fs.chmod(selected, 0o600);
  await fs.chmod(replacement, 0o600);
  const original = await fs.stat(selected),
    alternate = await fs.stat(replacement);
  assert.equal(original.size, alternate.size);
  assert.notEqual(original.ino, alternate.ino);
  const app = await createApplication({
      service: { name: 'pdf-font-identity', version: '1.0.0', environment: 'test' },
      plugins: [
        documentsPdfPlugin({
          defaults: {},
          fontAllowlist: [selected],
          policy: { maxConcurrent: 1, timeoutMs: 10000 },
        }),
      ],
    }),
    originalOpen = fs.open,
    originalLstat = fs.lstat,
    firstInode = 1n << 53n;
  let swapped = false,
    observed: { reads: () => number; closes: () => number; descriptor: () => number } | undefined;
  if (wide) {
    assert.notEqual(firstInode, firstInode + 1n);
    assert.equal(Number(firstInode), Number(firstInode + 1n));
    // Model native uint64 identities while preserving actual font bytes and descriptor I/O.
    context.mock.method(fs, 'lstat', (async (...arguments_: Parameters<typeof fs.lstat>) => {
      const value = await originalLstat(...arguments_);
      return arguments_[0] === selected ? wideMetadata(value, firstInode) : value;
    }) as typeof fs.lstat);
  }
  context.mock.method(fs, 'open', async (...arguments_: Parameters<typeof fs.open>) => {
    if (arguments_[0] === selected && replace && !swapped) {
      // Replace one real regular inode after lstat, preserving valid font bytes and mode.
      await fs.rename(replacement, selected);
      swapped = true;
    }
    const file = await originalOpen(...arguments_);
    if (arguments_[0] === selected && wide) {
      const stat = file.stat.bind(file);
      context.mock.method(file, 'stat', (async (...statArguments: Parameters<FileHandle['stat']>) =>
        wideMetadata(
          await stat(...statArguments),
          firstInode + (replace ? 1n : 0n),
        )) as FileHandle['stat']);
    }
    if (arguments_[0] === selected && !observed) {
      const reading = context.mock.method(file, 'read'),
        closing = context.mock.method(file, 'close');
      observed = {
        reads: () => reading.mock.callCount(),
        closes: () => closing.mock.callCount(),
        descriptor: () => file.fd,
      };
    }
    return file;
  });
  syncBuiltinESMExports();
  try {
    await app.start();
    const pdf = app.resolve<PdfService>(PDF_CAPABILITY),
      builder = pdf.create();
    builder.addText('Αθήνα', 1, 40, 100, {
      font: selected,
      size: 12,
      colorHex: '#000000',
    });
    if (replace)
      await assert.rejects(
        builder.save(),
        (error: unknown) => error instanceof KitError && error.code === 'EK_PDF_PARSE',
      );
    else {
      const pages = await pdf.extractText(await builder.save());
      assert.ok(
        pages[0]!.items
          .map((item) => item.text)
          .join(' ')
          .includes('Αθήνα'),
      );
    }
    assert.equal(swapped, replace);
    assert.ok(observed);
    if (replace) assert.equal(observed.reads(), 0);
    else assert.ok(observed.reads() > 0);
    assert.equal(observed.closes(), 1);
    assert.equal(observed.descriptor(), -1);
    assert.equal((await fs.stat(selected)).ino, replace ? alternate.ino : original.ino);
    context.mock.restoreAll();
    syncBuiltinESMExports();
    const recovered = pdf.create();
    recovered.addText('Αθήνα', 1, 40, 100, {
      font: selected,
      size: 12,
      colorHex: '#000000',
    });
    const pages = await pdf.extractText(await recovered.save());
    assert.ok(
      pages[0]!.items
        .map((item) => item.text)
        .join(' ')
        .includes('Αθήνα'),
    );
  } finally {
    context.mock.restoreAll();
    syncBuiltinESMExports();
    try {
      await app.stop();
    } finally {
      await fs.rm(directory, { recursive: true, force: true });
    }
  }
}

test(
  'Public PDF font loading rejects regular-file replacement before reading and recovers with the stable font',
  { timeout: 15000 },
  async (context) => verifyFont(context, false, true),
);

test(
  'Public PDF font loading distinguishes adjacent full-width inode identities',
  { timeout: 15000 },
  async (context) => verifyFont(context, true, true),
);

test(
  'Public PDF font loading accepts an unchanged full-width inode identity',
  { timeout: 15000 },
  async (context) => verifyFont(context, true, false),
);
