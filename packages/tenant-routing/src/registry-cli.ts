// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { isAbsolute } from 'node:path';
import type { Environment, OperationOptions } from '@arkenivajs/core';
import { tenantRegistryFileProvider } from './file-provider.js';

const help =
  'Usage: arkenivajs-tenant-registry validate --file ABSOLUTE_PATH [--environment production|development|test] [--max-bytes INTEGER] [--public-root ABSOLUTE_PATH]\n';

/** Offline deployment validation never starts an application or executes registry code. */
export async function runRegistryCli(
  args: readonly string[],
  output: Readonly<{ stdout(value: string): void; stderr(value: string): void }>,
  options: OperationOptions = {},
): Promise<number> {
  if (args.length === 1 && ['--help', '-h'].includes(args[0]!)) {
    output.stdout(help);
    return 0;
  }
  const fields = new Map<string, string>(),
    publicRoots: string[] = [];
  try {
    if (args[0] !== 'validate' || args.length > 1024 || args.length % 2 !== 1)
      throw new Error('Invalid command');
    for (let index = 1; index < args.length; index += 2) {
      const name = args[index]!,
        value = args[index + 1];
      if (
        !['--file', '--environment', '--max-bytes', '--public-root'].includes(name) ||
        value === undefined ||
        !value.length ||
        value.length > 4096
      )
        throw new Error('Invalid option');
      if (name === '--public-root') {
        if (!isAbsolute(value) || publicRoots.length >= 128) throw new Error('Invalid root');
        publicRoots.push(value);
      } else {
        if (fields.has(name)) throw new Error('Duplicate option');
        fields.set(name, value);
      }
    }
    if (!fields.get('--file') || !isAbsolute(fields.get('--file')!))
      throw new Error('Invalid file');
    if (
      fields.has('--environment') &&
      !['production', 'development', 'test'].includes(fields.get('--environment')!)
    )
      throw new Error('Invalid environment');
    if (
      fields.has('--max-bytes') &&
      (!/^[1-9][0-9]{0,8}$/.test(fields.get('--max-bytes')!) ||
        Number(fields.get('--max-bytes')) > 134217728)
    )
      throw new Error('Invalid bound');
  } catch {
    output.stderr(help);
    return 2;
  }
  try {
    const snapshot = await tenantRegistryFileProvider({
      absolutePath: fields.get('--file')!,
      maxBytes: fields.has('--max-bytes') ? Number(fields.get('--max-bytes')) : 8388608,
      environment: (fields.get('--environment') ?? 'production') as Environment,
      publicRoots,
    }).loadSnapshot(options);
    output.stdout(
      JSON.stringify({
        valid: true,
        schemaVersion: snapshot.schemaVersion,
        revision: snapshot.revision,
        activationGeneration: snapshot.activationGeneration,
        operations: snapshot.operations.length,
        bindings: snapshot.bindings.length,
      }) + '\n',
    );
    return 0;
  } catch {
    output.stderr('Tenant registry validation failed\n');
    return 1;
  }
}
