// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { mkdtemp, writeFile, truncate, symlink, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createFixedUpstreamPool, type FixedUpstreamPoolOptions } from '@arkenivajs/proxy/support';
import { tlsFixture } from '../tls-fixture.js';

const input: FixedUpstreamPoolOptions = {
  upstreamOrigin: 'https://127.0.0.1:443',
  destinationPolicy: {
    kind: 'private-allowlisted',
    allowedHosts: ['127.0.0.1'],
    allowedCidrs: ['127.0.0.1/32'],
  },
  connectionTimeoutMs: 1000,
};

test('The shared proxy transport retains strict host, CIDR and bounded connection policy', async () => {
  for (const patch of [
    { connectionTimeoutMs: 0 },
    { connectionTimeoutMs: 120001 },
    { connectionTimeoutMs: 1.5 },
    { upstreamOrigin: 'https://127.0.0.1/path' },
    { upstreamOrigin: 'https://user@127.0.0.1' },
    { destinationPolicy: { kind: 'public-only' } },
    { deniedCidrs: ['127.0.0.0/8'] },
    {
      destinationPolicy: {
        kind: 'private-allowlisted',
        allowedHosts: ['unrelated.test'],
        allowedCidrs: ['127.0.0.1/32'],
      },
    },
  ])
    await assert.rejects(
      createFixedUpstreamPool({ ...input, ...patch } as FixedUpstreamPoolOptions),
      { code: 'EK_PROXY_CONFIG' },
    );
});

test('The shared transport performs a real authenticated TLS handshake without creating a listener', async () => {
  const material = await tlsFixture(),
    server = createServer({ key: material.key, cert: material.cert }, (_request, response) => {
      response.setHeader('content-type', 'application/json');
      response.end('{"approved":true}');
    });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  const pool = await createFixedUpstreamPool({
    ...input,
    upstreamOrigin: 'https://127.0.0.1:' + address.port,
    upstreamCaFile: material.files.certificateFile,
  });
  try {
    const response = await pool.request({ method: 'GET', path: '/fixed' });
    assert.equal(response.statusCode, 200);
    assert.deepEqual(await response.body.json(), { approved: true });
  } finally {
    await pool.destroy();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await material.close();
  }
});

test('CA reads reject oversized sparse files, malformed PEM, symlinks and directories before pool construction', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-upstream-ca-'));
  try {
    const path = join(directory, 'ca.pem');
    await writeFile(path, 'not a certificate');
    await assert.rejects(createFixedUpstreamPool({ ...input, upstreamCaFile: path }), {
      code: 'EK_PROXY_CONFIG',
    });
    await truncate(path, 1048577);
    await assert.rejects(createFixedUpstreamPool({ ...input, upstreamCaFile: path }), {
      code: 'EK_PROXY_CONFIG',
    });
    const link = join(directory, 'linked.pem');
    await symlink(path, link);
    await assert.rejects(createFixedUpstreamPool({ ...input, upstreamCaFile: link }), {
      code: 'EK_PROXY_CONFIG',
    });
    const folder = join(directory, 'folder');
    await mkdir(folder);
    await assert.rejects(createFixedUpstreamPool({ ...input, upstreamCaFile: folder }), {
      code: 'EK_PROXY_CONFIG',
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
