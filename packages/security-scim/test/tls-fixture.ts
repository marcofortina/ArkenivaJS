// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { mkdtemp, chmod, readFile, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** Native ephemeral credentials exercise verified TLS without persistent host configuration. */
export async function tlsFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-scim-tls-'));
  await chmod(directory, 0o700);
  const certificateFile = join(directory, 'server.pem'),
    privateKeyFile = join(directory, 'server.key');
  try {
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '1',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-keyout',
        privateKeyFile,
        '-out',
        certificateFile,
      ],
      { timeout: 10000 },
    );
    await chmod(privateKeyFile, 0o600);
    await chmod(certificateFile, 0o400);
    return {
      files: { certificateFile, privateKeyFile },
      ca: await readFile(certificateFile),
      close: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
