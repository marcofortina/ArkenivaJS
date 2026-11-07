// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import fs from 'node:fs/promises';
import type { BigIntStats, Stats, StatOptions } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { KitError } from '@arkenivajs/core';

const scenario = process.argv[2]!,
  cwd = process.cwd(),
  path = join(cwd, 'package.json'),
  lockPath = join(cwd, '.wide-service.arkenivajs.lock'),
  originalOpen = fs.open,
  originalLstat = fs.lstat,
  inode = 2n ** 53n,
  timestamp = 1700000000000000000n,
  foreign = '{"name":"foreign","type":"module","dependencies":{"@arkenivajs/core":"0.1.0"}}\n';
let replaced = false,
  bigintCaptures = 0;

/** Only metadata precision is modeled; replacement, permission checks and reads are native. */
function metadata(value: Stats | BigIntStats, current: boolean): Stats | BigIntStats {
  const big = typeof value.ino === 'bigint',
    id =
      inode +
      (scenario === 'stable' ||
      (current && replaced && (scenario === 'replacement' || scenario === 'lock'))
        ? 1n
        : 0n),
    ns = timestamp + (current && scenario !== 'stable' ? 1n : 0n),
    result = Object.assign(
      Object.create(Object.getPrototypeOf(value)) as Stats | BigIntStats,
      value,
    );
  if (big) bigintCaptures++;
  Object.assign(result, {
    ino: big ? id : Number(id),
    mtimeMs: big ? timestamp / 1000000n : Number(timestamp) / 1000000,
    ctimeMs: big ? timestamp / 1000000n : Number(timestamp) / 1000000,
    mtime: new Date(Number(timestamp / 1000000n)),
    ctime: new Date(Number(timestamp / 1000000n)),
    ...(big
      ? {
          mtimeNs: scenario === 'mtime' ? ns : timestamp,
          ctimeNs: scenario === 'ctime' ? ns : timestamp,
        }
      : {}),
  });
  return result;
}

fs.open = (async (...args: Parameters<typeof fs.open>) => {
  const handle = await originalOpen(...args);
  if (args[0] === path || args[0] === lockPath) {
    const stat = handle.stat.bind(handle);
    handle.stat = (async (options?: StatOptions) =>
      metadata(
        options?.bigint ? await stat({ bigint: true }) : await stat(),
        false,
      )) as typeof handle.stat;
  }
  return handle;
}) as typeof fs.open;
fs.lstat = (async (name: Parameters<typeof fs.lstat>[0], options?: StatOptions) => {
  const target = scenario === 'lock' ? lockPath : path;
  if (name === target && scenario !== 'stable' && !replaced) {
    if (scenario === 'replacement' || scenario === 'lock') {
      const candidate = target + '.replacement';
      await fs.writeFile(candidate, scenario === 'lock' ? 'foreign lock' : foreign, {
        mode: 0o600,
      });
      await fs.rename(candidate, target);
    } else {
      await fs.writeFile(path, foreign, { mode: 0o640 });
    }
    replaced = true;
  }
  const value = options?.bigint
    ? await originalLstat(name, { bigint: true })
    : await originalLstat(name);
  return name === path || name === lockPath ? metadata(value, true) : value;
}) as typeof fs.lstat;
syncBuiltinESMExports();
const { addModule, newProject } = await import('../../dist/index.js');
let accepted = false,
  code: string | undefined;
try {
  if (scenario === 'lock') await newProject('wide-service', { cwd });
  else await addModule('dns', { cwd });
  accepted = true;
} catch (error) {
  code = error instanceof KitError ? error.code : undefined;
}
console.log(JSON.stringify({ accepted, replaced, bigintCaptures, code }));
