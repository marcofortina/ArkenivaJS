// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import {
  constants,
  lstatSync,
  openSync,
  fstatSync,
  readSync,
  closeSync,
  realpathSync,
} from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import protobuf from 'protobufjs';

/** Compile a bounded, offline graph with the approved native protobuf parser. */
function compile(entry: string): protobuf.INamespace {
  if (
    typeof entry !== 'string' ||
    entry.length > 4096 ||
    !isAbsolute(entry) ||
    resolve(entry) !== entry
  )
    throw new Error('Invalid descriptor path');
  const root = new protobuf.Root(),
    base = dirname(entry),
    visited = new Set<string>(),
    active = new Set<string>();
  let total = 0;
  function visit(path: string): void {
    if (active.has(path)) throw new Error('Cyclic descriptor import');
    if (visited.has(path)) return;
    if (visited.size >= 32) throw new Error('Descriptor import limit exceeded');
    visited.add(path);
    active.add(path);
    const before = lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink() || realpathSync(path) !== path)
      throw new Error('Untrusted descriptor asset');
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let source: string;
    try {
      const stat = fstatSync(fd);
      if (
        !stat.isFile() ||
        stat.size < 1 ||
        stat.size > 1048576 ||
        stat.mode & 0o022 ||
        (stat.uid !== 0 && stat.uid !== process.getuid?.()) ||
        stat.dev !== before.dev ||
        stat.ino !== before.ino
      )
        throw new Error('Invalid descriptor asset');
      total += stat.size;
      if (total > 8388608) throw new Error('Descriptor graph size exceeded');
      const bytes = Buffer.alloc(stat.size);
      let offset = 0;
      while (offset < bytes.length) {
        const count = readSync(fd, bytes, offset, bytes.length - offset, offset);
        if (!count) throw new Error('Incomplete descriptor asset');
        offset += count;
      }
      source = bytes.toString('utf8');
      if (!Buffer.from(source).equals(bytes)) throw new Error('Invalid descriptor encoding');
      const after = fstatSync(fd);
      if (
        after.size !== stat.size ||
        after.mtimeMs !== stat.mtimeMs ||
        after.ctimeMs !== stat.ctimeMs
      )
        throw new Error('Descriptor changed during capture');
    } finally {
      closeSync(fd);
    }
    const parsed = protobuf.parse(source, root, { keepCase: true });
    for (const reference of [...(parsed.imports ?? []), ...(parsed.weakImports ?? [])]) {
      const bundled = protobuf.common.get(reference);
      if (bundled) {
        if (!visited.has(reference)) {
          visited.add(reference);
          root.addJSON(bundled.nested ?? {});
        }
        continue;
      }
      if (
        !/^[A-Za-z0-9_./-]+$/.test(reference) ||
        reference.startsWith('/') ||
        reference.split('/').some((part) => !part)
      )
        throw new Error('Invalid descriptor import');
      const target = resolve(dirname(path), reference),
        inside = relative(base, target);
      if (!inside || inside === '..' || inside.startsWith('../') || isAbsolute(inside))
        throw new Error('Descriptor import escaped its root');
      visit(target);
    }
    active.delete(path);
  }
  visit(entry);
  root.resolveAll();
  return root.toJSON();
}
try {
  parentPort?.postMessage({ ok: true, schema: compile((workerData as { entry: string }).entry) });
} catch {
  parentPort?.postMessage({ ok: false });
} finally {
  parentPort?.close();
}
