// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants } from 'node:fs';
import type { BigIntStats } from 'node:fs';
import fs from 'node:fs/promises';
import { TextDecoder } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { captureAbortSignal } from '@arkenivajs/core/support';

const invalid = () =>
  new KitError({
    code: 'EK_CONFIG_INVALID',
    message: 'Configuration file changed or exceeds its byte limit',
  });
const same = (left: BigIntStats, right: BigIntStats) =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.size === right.size &&
  left.mtimeNs === right.mtimeNs &&
  left.ctimeNs === right.ctimeNs;

/** Read the validated inode through one descriptor with a fixed allocation and an explicit EOF check. */
export async function readConfigurationFile(
  path: string,
  inputSignal?: AbortSignal,
): Promise<string> {
  const signal = inputSignal === undefined ? undefined : captureAbortSignal(inputSignal);
  const check = () => {
    if (signal?.aborted)
      throw new KitError({ code: 'EK_ABORTED', message: 'Configuration file read was cancelled' });
  };
  check();
  const before = await fs.lstat(path, { bigint: true });
  if (!before.isFile() || before.size > 1048576n || (await fs.realpath(path)) !== path)
    throw invalid();
  check();
  const file = await fs.open(
    path,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const opened = await file.stat({ bigint: true });
    if (!opened.isFile() || !same(before, opened) || opened.size < 0n || opened.size > 1048576n)
      throw invalid();
    const data = Buffer.alloc(Number(opened.size)),
      extra = Buffer.alloc(1);
    try {
      let position = 0;
      while (position < data.length) {
        check();
        const { bytesRead } = await file.read(data, position, data.length - position, position);
        if (!bytesRead) throw invalid();
        position += bytesRead;
      }
      check();
      if (
        (await file.read(extra, 0, 1, position)).bytesRead ||
        !same(opened, await file.stat({ bigint: true }))
      )
        throw invalid();
      check();
      return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data);
    } finally {
      data.fill(0);
      extra.fill(0);
    }
  } finally {
    await file.close();
  }
}
