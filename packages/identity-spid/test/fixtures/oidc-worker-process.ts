// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { execFile, fork } from 'node:child_process';
import { promisify } from 'node:util';
import { once } from 'node:events';
import { mkdtemp, rm, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

export async function runOidcWorker(mapping = false) {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-eid-callback-')),
    certificate = join(directory, 'certificate.pem'),
    privateKey = join(directory, 'key.pem');
  try {
    await promisify(execFile)(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-noenc',
        '-days',
        '1',
        '-subj',
        '/CN=127.0.0.1',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-keyout',
        privateKey,
        '-out',
        certificate,
      ],
      { timeout: 10000 },
    );
    await Promise.all([chmod(privateKey, 0o600), chmod(certificate, 0o600)]);
    const child = fork(new URL('../fixtures/oidc-callback-worker.js', import.meta.url), [], {
      execArgv: [],
      env: { ...process.env, NODE_EXTRA_CA_CERTS: certificate },
      stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    });
    let diagnostics = '';
    child.stderr?.on('data', (chunk: Buffer) => {
      if (diagnostics.length < 8192) diagnostics += chunk.toString();
    });
    try {
      const evidence = Promise.race([
        once(child, 'message'),
        once(child, 'exit').then(() => {
          throw new Error('OIDC worker exited before evidence: ' + diagnostics);
        }),
      ]);
      child.send({ certificate, privateKey, mapping });
      assert.deepEqual((await evidence)[0], { ok: true });
      await once(child, 'exit');
    } finally {
      child.kill();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
