// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import fs from 'node:fs';
import type { BigIntStats, Stats, StatOptions } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { parentPort, workerData } from 'node:worker_threads';

const { entry, scenario } = workerData as { entry: string; scenario: string },
  originalLstat = fs.lstatSync,
  originalFstat = fs.fstatSync,
  originalOpen = fs.openSync,
  originalRead = fs.readSync,
  inode = 2n ** 53n,
  timestamp = 1700000000000000000n;
let ownedFd = -1,
  replaced = false,
  changed = false,
  captures = 0;

/** Model legal uint64 metadata while retaining real native file operations and file type. */
function metadata(value: Stats | BigIntStats, opened: boolean): Stats | BigIntStats {
  const big = typeof value.ino === 'bigint',
    id = inode + (scenario === 'stable' || (opened && replaced) ? 1n : 0n),
    ns = timestamp + (changed ? 1n : 0n),
    result = Object.assign(
      Object.create(Object.getPrototypeOf(value)) as Stats | BigIntStats,
      value,
    );
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

Object.defineProperty(fs, 'lstatSync', {
  value: ((path: fs.PathLike, options?: StatOptions) => {
    const value = options?.bigint ? originalLstat(path, { bigint: true }) : originalLstat(path);
    if (path !== entry) return value;
    const before = metadata(value, false);
    if (scenario === 'replacement') {
      const candidate = entry + '.replacement';
      fs.writeFileSync(candidate, 'syntax="proto3"; message Other { string value=1; }', {
        mode: 0o600,
      });
      fs.renameSync(candidate, entry);
      replaced = true;
      parentPort?.postMessage({ event: 'actual-replacement' });
    }
    return before;
  }) as typeof fs.lstatSync,
});
fs.openSync = ((...args: Parameters<typeof fs.openSync>) => {
  const fd = originalOpen(...args);
  if (
    args[0] === entry &&
    typeof args[1] === 'number' &&
    (args[1] & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0
  )
    ownedFd = fd;
  return fd;
}) as typeof fs.openSync;
fs.fstatSync = ((fd: number, options?: StatOptions) => {
  const value = options?.bigint ? originalFstat(fd, { bigint: true }) : originalFstat(fd);
  if (fd !== ownedFd) return value;
  captures++;
  parentPort?.postMessage({ event: 'capture', bigint: options?.bigint === true, captures });
  return metadata(value, true);
}) as typeof fs.fstatSync;
fs.readSync = ((...args: Parameters<typeof fs.readSync>) => {
  const count = originalRead(...args);
  if (args[0] === ownedFd && !changed && (scenario === 'mtime' || scenario === 'ctime')) {
    fs.writeFileSync(entry, 'syntax="proto3"; message Other { string value=1; }', { mode: 0o600 });
    changed = true;
    parentPort?.postMessage({ event: 'actual-write' });
  }
  return count;
}) as typeof fs.readSync;
syncBuiltinESMExports();
await import('../../dist/descriptor-worker.js');
