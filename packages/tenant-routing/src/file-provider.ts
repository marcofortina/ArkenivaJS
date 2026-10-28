// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, parse, relative, resolve, sep } from 'node:path';
import { TextDecoder, types } from 'node:util';
import type {
  TenantRegistryFileOptions,
  TenantRegistryProvider,
  TenantRegistrySnapshotV1_1,
} from './contracts.js';
import { registryFailure } from './errors.js';
import { ActivationHistory, data, registryOperation } from './provider-support.js';

function absolute(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.length ||
    value.length > 4096 ||
    !isAbsolute(value) ||
    value.includes('\0') ||
    resolve(value) !== value
  )
    throw registryFailure();
  return value;
}
function contains(root: string, path: string) {
  const child = relative(root, path);
  return child === '' || (!child.startsWith('..' + sep) && child !== '..' && !isAbsolute(child));
}

/** Startup-only file provider. Runtime requests never consult the filesystem registry. */
export function tenantRegistryFileProvider(
  input: TenantRegistryFileOptions,
): TenantRegistryProvider {
  try {
    const fields = data(input, [
      'absolutePath',
      'maxBytes',
      'activationCheckpoint',
      'environment',
      'publicRoots',
    ]);
    const path = absolute(fields.absolutePath),
      maxBytes = fields.maxBytes;
    if (
      !Number.isSafeInteger(maxBytes) ||
      (maxBytes as number) < 1 ||
      (maxBytes as number) > 134217728
    )
      throw registryFailure();
    const environment = fields.environment === undefined ? 'production' : fields.environment;
    if (!['production', 'development', 'test'].includes(environment as string))
      throw registryFailure();
    const roots = fields.publicRoots === undefined ? [] : fields.publicRoots;
    if (types.isProxy(roots) || !Array.isArray(roots) || roots.length > 128)
      throw registryFailure();
    // Capture values as plain data; accessors, holes and caller mutations cannot alter the policy.
    const rootFields = Object.getOwnPropertyDescriptors(roots);
    if (Reflect.ownKeys(rootFields).length !== roots.length + 1) throw registryFailure();
    const publicRoots: string[] = [];
    for (let index = 0; index < roots.length; index++) {
      const field = rootFields[index];
      if (!field || !('value' in field) || !field.enumerable) throw registryFailure();
      publicRoots.push(absolute(field.value));
    }
    if (publicRoots.some((root) => contains(root, path))) throw registryFailure();
    const history = new ActivationHistory(
      fields.activationCheckpoint as TenantRegistryFileOptions['activationCheckpoint'],
    );
    const scope = 'file:' + createHash('sha256').update(path).digest('hex');
    let loading = false;
    return Object.freeze({
      async loadSnapshot(options) {
        if (loading) throw registryFailure();
        loading = true;
        let started = false;
        try {
          return await registryOperation(async (operation, check) => {
            started = true;
            try {
              check();
              for (const root of publicRoots)
                if (contains(await realpath(root), path)) throw registryFailure();
              const production = environment === 'production';
              const root = parse(path).root;
              let directory = root;
              const directories = [root];
              for (const part of relative(root, dirname(path)).split(sep).filter(Boolean)) {
                directory = resolve(directory, part);
                directories.push(directory);
              }
              for (const parent of directories) {
                check();
                const info = await lstat(parent);
                if (
                  !info.isDirectory() ||
                  info.isSymbolicLink() ||
                  (production && (info.uid !== 0 || (info.mode & 0o022) !== 0))
                )
                  throw registryFailure();
              }
              if ((await realpath(path)) !== path) throw registryFailure();
              check();
              const before = await lstat(path, { bigint: true });
              let snapshot: TenantRegistrySnapshotV1_1;
              const file = await open(
                path,
                constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
              );
              try {
                const info = await file.stat({ bigint: true });
                if (
                  !info.isFile() ||
                  info.size < 1n ||
                  info.size > BigInt(maxBytes as number) ||
                  info.nlink !== 1n ||
                  (info.mode & 0o7137n) !== 0n ||
                  (production && info.uid !== 0n) ||
                  info.ino !== before.ino ||
                  info.dev !== before.dev
                )
                  throw registryFailure();
                const content = Buffer.alloc(Number(info.size));
                try {
                  let position = 0;
                  while (position < content.length) {
                    check();
                    const read = await file.read(
                      content,
                      position,
                      content.length - position,
                      position,
                    );
                    if (!read.bytesRead) throw registryFailure();
                    position += read.bytesRead;
                  }
                  if ((await file.read(Buffer.alloc(1), 0, 1, position)).bytesRead)
                    throw registryFailure();
                  const after = await file.stat({ bigint: true }),
                    named = await lstat(path, { bigint: true });
                  if (
                    after.size !== info.size ||
                    after.mtimeNs !== info.mtimeNs ||
                    after.ctimeNs !== info.ctimeNs ||
                    named.ino !== info.ino ||
                    named.dev !== info.dev ||
                    (await realpath(path)) !== path
                  )
                    throw registryFailure();
                  check();
                  const { parseRegistry } = await import('./registry.js');
                  check();
                  snapshot = parseRegistry(
                    new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(content),
                    maxBytes as number,
                  );
                  check();
                } finally {
                  content.fill(0);
                }
              } finally {
                await file.close();
              }
              await history.accept(snapshot, scope, operation, check);
              return snapshot;
            } finally {
              loading = false;
            }
          }, options);
        } catch {
          throw registryFailure();
        } finally {
          if (!started) loading = false;
        }
      },
    } satisfies TenantRegistryProvider);
  } catch {
    throw registryFailure();
  }
}
