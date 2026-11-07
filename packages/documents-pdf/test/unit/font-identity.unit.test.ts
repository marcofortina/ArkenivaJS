// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { KitError, createApplication } from '@arkenivajs/core';
import { documentsPdfPlugin, PDF_CAPABILITY } from '../../dist/index.js';
import type { PdfService } from '../../dist/index.js';

test(
  'Public PDF font loading rejects regular-file replacement before reading and recovers with the stable font',
  { timeout: 15000 },
  async (context) => {
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
      originalOpen = fs.open;
    let swapped = false,
      observed: { reads: () => number; closes: () => number; descriptor: () => number } | undefined;
    const opening = context.mock.method(
      fs,
      'open',
      async (...arguments_: Parameters<typeof fs.open>) => {
        if (arguments_[0] === selected && !swapped) {
          // Replace one real regular inode after lstat, preserving valid font bytes and mode.
          await fs.rename(replacement, selected);
          swapped = true;
        }
        const file = await originalOpen(...arguments_);
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
      },
    );
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
      await assert.rejects(
        builder.save(),
        (error: unknown) => error instanceof KitError && error.code === 'EK_PDF_PARSE',
      );
      assert.equal(swapped, true);
      assert.ok(observed);
      assert.equal(observed.reads(), 0);
      assert.equal(observed.closes(), 1);
      assert.equal(observed.descriptor(), -1);
      assert.equal((await fs.stat(selected)).ino, alternate.ino);
      opening.mock.restore();
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
      opening.mock.restore();
      syncBuiltinESMExports();
      try {
        await app.stop();
      } finally {
        await fs.rm(directory, { recursive: true, force: true });
      }
    }
  },
);
