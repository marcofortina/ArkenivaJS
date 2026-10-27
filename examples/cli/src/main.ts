// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mkdtemp, mkdir, symlink, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { newProject, addModule } from '@arkenivajs/cli';
import type { Application } from '@arkenivajs/core';

const require = createRequire(import.meta.url),
  execute = promisify(execFile);
const packageRoot = (name: string) => dirname(dirname(fileURLToPath(import.meta.resolve(name))));

/** Link only already installed consumer artifacts; no registry request, installation or publication. */
async function linkConsumerDependencies(directory: string) {
  await mkdir(join(directory, 'node_modules/@arkenivajs'), { recursive: true });
  for (const name of ['core', 'api', 'logging'])
    await symlink(
      packageRoot('@arkenivajs/' + name),
      join(directory, 'node_modules/@arkenivajs', name),
      'dir',
    );
  await mkdir(join(directory, 'node_modules/@types'));
  await symlink(
    dirname(require.resolve('@types/node/package.json')),
    join(directory, 'node_modules/@types/node'),
    'dir',
  );
}

/** Compile and execute the produced starter against the consumer's actual installed framework packages. */
export async function exerciseCli() {
  const root = await mkdtemp(join(tmpdir(), 'arkeniva-cli-consumer-'));
  let app: Application | undefined;
  try {
    const created = await newProject('owned-service', { cwd: root });
    const source = await readFile(join(created.directory, 'src/main.ts'), 'utf8');
    const added = await addModule('dns', { cwd: created.directory });
    const repeated = await addModule('dns', { cwd: created.directory });
    await linkConsumerDependencies(created.directory);
    await execute(
      process.execPath,
      [require.resolve('typescript/bin/tsc'), '-p', join(created.directory, 'tsconfig.json')],
      { timeout: 30000, maxBuffer: 1048576 },
    );
    const module = (await import(pathToFileURL(join(created.directory, 'dist/main.js')).href)) as {
      createService(port: number): Promise<Application>;
    };
    let greeting: unknown;
    for (let attempt = 0; attempt < 4; attempt++) {
      const reservation = createServer();
      reservation.listen(0, '127.0.0.1');
      await once(reservation, 'listening');
      const address = reservation.address();
      if (!address || typeof address === 'string')
        throw new Error('The owned port reservation failed');
      await new Promise<void>((fulfill, reject) =>
        reservation.close((error) => (error ? reject(error) : fulfill())),
      );
      app = await module.createService(address.port);
      try {
        await app.start();
        const response = await fetch(`http://127.0.0.1:${address.port}/hello`, {
          signal: AbortSignal.timeout(5000),
        });
        if (response.status !== 200) throw new Error('The starter did not return a greeting');
        greeting = await response.json();
        break;
      } catch (error) {
        await app.stop().catch(() => undefined);
        app = undefined;
        if (
          !(error instanceof Error) ||
          !JSON.stringify(error).includes('EADDRINUSE') ||
          attempt === 3
        )
          throw error;
      }
    }
    const bin = join(packageRoot('@arkenivajs/cli'), 'dist/bin.js');
    const help = await execute(process.execPath, [bin, '--help'], { timeout: 5000 });
    return {
      greeting,
      dependencyAdded: added.changed,
      idempotent: !repeated.changed,
      sourceUnchanged: source === (await readFile(join(created.directory, 'src/main.ts'), 'utf8')),
      packageBin: help.stdout.startsWith('Usage: arkenivajs'),
    };
  } finally {
    try {
      await app?.stop();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void exerciseCli().then(
    (result) => {
      console.log(JSON.stringify(result));
    },
    () => {
      console.error('The CLI consumer example could not complete');
      process.exitCode = 1;
    },
  );
}
