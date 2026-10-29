// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { createRequire, syncBuiltinESMExports } from 'node:module';
import { setImmediate } from 'node:timers/promises';
import { readFile } from 'node:fs/promises';
import { verify } from 'node:crypto';
import type { Worker, WorkerOptions } from 'node:worker_threads';
import { fixture } from '../fixture.js';
import { createManagedSamlAdapter } from '../../dist/support.js';

// This disposable process alone replaces the constructor; all cryptographic work stays native.
const threads = createRequire(import.meta.url)('node:worker_threads') as { Worker: typeof Worker },
  NativeWorker = threads.Worker,
  f = await fixture(),
  certificate = await readFile(f.directory + '/sp.pem'),
  held = new Set<ControlledWorker>();
let reached!: () => void;
const ready = new Promise<void>((resolve) => {
  reached = resolve;
});

class ControlledWorker extends NativeWorker {
  exited = false;
  constructor(filename: URL, options: WorkerOptions) {
    // Keep the actual thread alive after the actual SDK closes its message port.
    super('setInterval(() => {}, 1000); void import(' + JSON.stringify(filename.href) + ');', {
      ...options,
      eval: true,
    });
    held.add(this);
    this.once('exit', () => {
      this.exited = true;
    });
    this.once('message', (message: { ok: boolean; result?: { kind: string; url: string } }) => {
      assert.equal(message.ok, true);
      assert.equal(message.result?.kind, 'redirect');
      const target = new URL(message.result!.url),
        signed = target.search
          .slice(1)
          .split('&')
          .filter((field) => !field.startsWith('Signature='))
          .join('&');
      assert.equal(
        verify(
          'RSA-SHA256',
          Buffer.from(signed),
          certificate,
          Buffer.from(target.searchParams.get('Signature')!, 'base64'),
        ),
        true,
      );
      reached();
    });
  }
  override terminate(): Promise<number> {
    return Promise.reject(new Error('The disposable termination request was rejected'));
  }
}

threads.Worker = ControlledWorker;
syncBuiltinESMExports();
const adapter = createManagedSamlAdapter(f.settings, new AbortController().signal, () => true);
let publicSettled = false,
  drained = false;
let task: Promise<string> | undefined, draining: Promise<void> | undefined;
try {
  await adapter.bootstrap();
  task = adapter.service.beginLogin({ returnPath: '/' }, { timeoutMs: 3000 }).then(
    () => {
      publicSettled = true;
      return 'success';
    },
    (error: { code: string }) => {
      publicSettled = true;
      return error.code;
    },
  );
  await Promise.race([
    ready,
    task.then(() => {
      throw new Error('Native work settled before its actual signed request');
    }),
  ]);
  await setImmediate();
  const settledBeforeDrain = publicSettled;
  if (process.argv[2] === 'drain') {
    draining = adapter.drain().then(() => {
      drained = true;
    });
  }
  await setImmediate();
  const observed = {
    settledBeforeDrain,
    drained,
    exited: [...held].every((worker) => worker.exited),
  };
  process.stdout.write(JSON.stringify(observed) + '\n');
  assert.deepEqual(observed, { settledBeforeDrain: false, drained: false, exited: false });
  if (draining) {
    assert.equal(await task, 'EK_ABORTED');
    assert.equal(drained, false);
  } else {
    for (const worker of held) await NativeWorker.prototype.terminate.call(worker);
    // The public native step preserves its existing sanitized assertion-error mapping.
    assert.equal(await task, 'EK_SAML_ASSERTION');
    draining = adapter.drain().then(() => {
      drained = true;
    });
  }
} finally {
  // Bypass only the rejecting test override, then await each real operating-system thread exit.
  for (const worker of held)
    if (!worker.exited) await NativeWorker.prototype.terminate.call(worker);
  if (task) await task;
  if (draining) await draining;
  else await adapter.drain();
  threads.Worker = NativeWorker;
  syncBuiltinESMExports();
  await f.close();
}
assert.equal(drained, true);
assert.equal(
  [...held].every((worker) => worker.exited),
  true,
);
