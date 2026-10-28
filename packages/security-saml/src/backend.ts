// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Worker } from 'node:worker_threads';
import { failure } from './validation.js';
import type { NativeRequest, NativeResult } from './backend-contracts.js';

/** Isolate native XML/debug output and make CPU-bound verification physically cancellable. */
export async function native(input: NativeRequest, signal: AbortSignal): Promise<NativeResult> {
  if (signal.aborted) throw failure('EK_ABORTED');
  const worker = new Worker(new URL('./worker.js', import.meta.url), {
    workerData: input,
    env: { NODE_ENV: 'production' },
    stdout: true,
    stderr: true,
    resourceLimits: { maxOldGenerationSizeMb: 64, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
  });
  worker.stdout.resume();
  worker.stderr.resume();
  return new Promise<NativeResult>((resolve, reject) => {
    let settled = false;
    const finish = async (result?: NativeResult, error?: unknown) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', abort);
      try {
        await worker.terminate();
      } catch {
        reject(failure('EK_BACKEND_UNAVAILABLE'));
        return;
      }
      if (error !== undefined) reject(error);
      else if (result) resolve(result);
      else reject(failure('EK_SAML_ASSERTION'));
    };
    const abort = () => {
      void finish(undefined, failure('EK_ABORTED'));
    };
    worker.once('message', (value: { ok: boolean; result?: NativeResult; code?: string }) => {
      if (value.ok && value.result) void finish(value.result);
      else
        void finish(
          undefined,
          failure(value.code === 'EK_SAML_SIGNATURE' ? 'EK_SAML_SIGNATURE' : 'EK_SAML_ASSERTION'),
        );
    });
    worker.once('error', () => {
      void finish(undefined, failure('EK_SAML_ASSERTION'));
    });
    worker.once('exit', () => {
      if (!settled) void finish(undefined, failure('EK_SAML_ASSERTION'));
    });
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
  });
}
