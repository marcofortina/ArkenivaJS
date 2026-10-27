// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFile } from 'node:fs/promises';
import { KitError } from '@arkenivajs/core';
import { openReader, createWriter } from './backend.js';
import type { ReaderBackend, WriterBackend } from './backend.js';
import type { XlsxRow } from './contracts.js';
import { options } from './settings.js';
import { fields, failure, integer, bytes, text } from './validation.js';
import { row } from './cells.js';

let reader: ReaderBackend | undefined,
  writer: WriterBackend | undefined,
  cursor: AsyncGenerator<XlsxRow> | undefined,
  output: Buffer[] = [],
  position = 0,
  working = false;
const allowed = new Set(['EK_XLSX_FORMAT', 'EK_XLSX_LIMIT', 'EK_XLSX_UNSUPPORTED']);
function send(value: object): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!process.send || !process.connected) return reject(failure());
    process.send({ ...value, memoryBytes: process.memoryUsage().rss }, (error) =>
      error ? reject(failure()) : resolve(),
    );
  });
}
async function command(raw: unknown): Promise<void> {
  const message = fields(raw, ['id', 'command', 'value']),
    id = integer(message.id, Number.MAX_SAFE_INTEGER),
    data = fields(message.value ?? {});
  try {
    let result: unknown = null;
    switch (message.command) {
      case 'open': {
        if (reader || writer) throw failure();
        const policy = options(data.options as Parameters<typeof options>[0]),
          maximum = integer(data.maximum, 256 * 1024 * 1024),
          input =
            data.path === undefined
              ? bytes(data.bytes, maximum)
              : await readFile(text(data.path, 4096));
        if (input.length > maximum) throw failure('EK_XLSX_LIMIT');
        try {
          reader = await openReader(input, policy);
        } catch (error) {
          input.fill(0);
          throw error;
        }
        result = reader.names;
        break;
      }
      case 'create':
        if (reader || writer) throw failure();
        writer = createWriter(
          options(data.options as Parameters<typeof options>[0]),
          integer(data.maximum, 256 * 1024 * 1024),
        );
        break;
      case 'sheet':
        if (!writer) throw failure();
        writer.addSheet(text(data.name, 124));
        break;
      case 'append':
        if (!writer) throw failure();
        writer.addRows(integer(data.index, 255, 0), [
          row(data.row, options(data.options as Parameters<typeof options>[0])),
        ]);
        break;
      case 'begin':
        if (!reader || cursor) throw failure('EK_XLSX_UNSUPPORTED');
        cursor = reader.rows(text(data.name, 124));
        break;
      case 'next': {
        if (!cursor) throw failure();
        const next = await cursor.next();
        if (next.done) cursor = undefined;
        else if (Buffer.byteLength(JSON.stringify(next.value)) > 2 * 1024 * 1024)
          throw failure('EK_XLSX_LIMIT');
        result = { done: !!next.done, ...(next.done ? {} : { value: next.value }) };
        break;
      }
      case 'finish': {
        if (!writer) throw failure();
        const finished = await writer.finish();
        output = finished.chunks;
        result = finished.receipt;
        break;
      }
      case 'chunk':
        result = position < output.length ? output[position++]! : null;
        break;
      case 'close':
        await cursor?.return(undefined);
        reader?.close();
        writer?.close();
        await send({ id, value: null });
        process.disconnect();
        return;
      default:
        throw failure();
    }
    await send({ id, value: result });
  } catch (error) {
    const code =
      error instanceof KitError && allowed.has(error.code) ? error.code : 'EK_XLSX_FORMAT';
    await send({ id, error: code });
  }
}
process.on('message', (raw: unknown) => {
  if (working) {
    process.disconnect();
    return;
  }
  working = true;
  void command(raw)
    .catch(() => {
      if (process.connected) process.disconnect();
    })
    .finally(() => {
      working = false;
    });
});
process.on('disconnect', () => {
  reader?.close();
  writer?.close();
});
