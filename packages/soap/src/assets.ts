// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { toUSVString } from 'node:util';
import { inspectXml, inspectWsdl } from './xml.js';
import { failure } from './validation.js';

export interface ContractAsset {
  readonly path: string;
  readonly source: string;
}
export interface ContractAssets {
  readonly entry: string;
  /** Dependencies precede their importers; every entry is an immutable captured document. */
  readonly documents: readonly ContractAsset[];
}
export function importedPath(source: string, reference: string, root: string): string {
  if (
    !reference ||
    reference.length > 4096 ||
    !/^[A-Za-z0-9_./-]+$/.test(reference) ||
    reference.startsWith('/') ||
    reference.split('/').some((part) => !part)
  )
    throw failure();
  const target = resolve(dirname(source), reference),
    inside = relative(root, target);
  if (!inside || inside === '..' || inside.startsWith('../') || isAbsolute(inside)) throw failure();
  return target;
}
async function readAsset(path: string, signal: AbortSignal): Promise<string> {
  if (signal.aborted) throw failure('EK_ABORTED');
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || (await realpath(path)) !== path)
    throw failure();
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      stat.size < 1 ||
      stat.size > 1048576 ||
      stat.mode & 0o022 ||
      (stat.uid !== 0 && stat.uid !== process.getuid?.()) ||
      stat.dev !== before.dev ||
      stat.ino !== before.ino
    )
      throw failure();
    const data = Buffer.alloc(stat.size);
    try {
      let position = 0;
      while (position < data.length) {
        if (signal.aborted) throw failure('EK_ABORTED');
        const { bytesRead } = await file.read(data, position, data.length - position, position);
        if (!bytesRead) throw failure();
        position += bytesRead;
      }
      const after = await file.stat();
      if (
        after.size !== stat.size ||
        after.mtimeMs !== stat.mtimeMs ||
        after.ctimeMs !== stat.ctimeMs ||
        signal.aborted
      )
        throw failure();
      const source = data.toString('utf8');
      if (!Buffer.from(source).equals(data) || toUSVString(source) !== source) throw failure();
      return source;
    } finally {
      data.fill(0);
    }
  } finally {
    await file.close();
  }
}

/** Capture only bounded local descendants before any native compiler can process an import. */
export async function loadAssets(entry: string, signal: AbortSignal): Promise<ContractAssets> {
  try {
    if (
      typeof entry !== 'string' ||
      entry.length > 4096 ||
      !isAbsolute(entry) ||
      resolve(entry) !== entry
    )
      throw failure();
    const root = dirname(entry),
      documents: ContractAsset[] = [],
      seen = new Set<string>(),
      visiting = new Set<string>();
    let total = 0;
    async function visit(path: string): Promise<void> {
      if (signal.aborted) throw failure('EK_ABORTED');
      if (visiting.has(path)) throw failure();
      if (seen.has(path)) return;
      if (seen.size >= 32) throw failure();
      seen.add(path);
      visiting.add(path);
      const source = await readAsset(path, signal);
      total += Buffer.byteLength(source);
      if (total > 8388608) throw failure();
      const inventory = path === entry ? inspectWsdl(source) : inspectXml(source);
      if (
        path !== entry &&
        !(
          (inventory.root.local === 'schema' &&
            inventory.root.uri === 'http://www.w3.org/2001/XMLSchema') ||
          (inventory.root.local === 'definitions' &&
            inventory.root.uri === 'http://schemas.xmlsoap.org/wsdl/')
        )
      )
        throw failure();
      for (const reference of inventory.imports) await visit(importedPath(path, reference, root));
      documents.push(Object.freeze({ path, source }));
      visiting.delete(path);
    }
    await visit(entry);
    if (signal.aborted) throw failure('EK_ABORTED');
    return Object.freeze({ entry, documents: Object.freeze(documents) });
  } catch {
    throw failure(signal.aborted ? 'EK_ABORTED' : 'EK_SOAP_WSDL');
  }
}
