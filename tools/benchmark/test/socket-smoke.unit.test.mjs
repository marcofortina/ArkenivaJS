// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, access, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  nativeSocket,
  prepareSocketEcho,
  socketEchoWorkload,
  completeSocketEcho,
} from '../socket-workload.mjs';

test('Socket sampling refuses unmarked execution before PKI or report allocation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-socket-entry-')),
    output = join(directory, 'report'),
    env = { ...process.env };
  delete env.ARKENIVA_SOCKET_BENCHMARK_DISPOSABLE;
  try {
    await assert.rejects(
      promisify(execFile)(
        process.execPath,
        [fileURLToPath(new URL('../socket.mjs', import.meta.url)), '--smoke', output],
        { env, timeout: 5000 },
      ),
      (cause) => {
        assert.match(cause.stderr, /Socket smoke requires an explicitly disposable/);
        return true;
      },
    );
    await assert.rejects(access(output));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Sampled TCP echo awaits an actual independent client and rejects incomplete sample evidence', async () => {
  const service = nativeSocket();
  try {
    await prepareSocketEcho(service, { marker: 'owned-socket-sample-control' });
    await assert.rejects(prepareSocketEcho(service, { marker: 'owned-duplicate-control' }));
    const callback = socketEchoWorkload(service).tcp64IndependentClient;
    const running = callback();
    await assert.rejects(callback());
    const value = await running;
    assert.equal(value.receivedBytes, 64);
    assert.equal(value.byteIdentityVerified, true);
    assert.ok(value.firstByteMs >= 0);
    assert.ok(value.exchangeElapsedMs >= value.firstByteMs);
    await assert.rejects(completeSocketEcho(service, { measure: true, records: [] }));
    await assert.rejects(callback());
    assert.throws(() => socketEchoWorkload(service));
  } finally {
    await service.close();
  }
});
