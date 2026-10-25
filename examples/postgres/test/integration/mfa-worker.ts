// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { TestContext } from 'node:test';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

/** Start only the supplied static test script; release its stdin barrier after peers are ready. */
export function startMfaWorker(t: TestContext, script: string, context: unknown) {
  const child = spawn(
    process.execPath,
    ['--input-type=module', '-e', script, JSON.stringify(context)],
    {
      cwd: fileURLToPath(new URL('../../', import.meta.url)),
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  t.after(() => {
    if (child.exitCode === null) child.kill('SIGTERM');
  });
  let resolveReady: () => void, rejectReady: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  let payload: unknown,
    received = false,
    diagnostic = '';
  const lines = createInterface({ input: child.stdout });
  let rejectResult: (error: Error) => void;
  const result = new Promise<unknown>((resolve, reject) => {
    rejectResult = reject;
    child.once('error', (error) => {
      rejectReady(error);
      reject(error);
    });
    child.once('close', (code) => {
      lines.close();
      if (code !== 0 || !received) {
        const error = new Error('MFA worker failed: ' + diagnostic);
        rejectReady(error);
        reject(error);
      } else resolve(payload);
    });
  });
  const exit = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.once('close', (code, signal) => resolve({ code, signal }));
  });
  lines.on('line', (line) => {
    try {
      if (line.length > 4096) throw new Error('MFA worker response exceeds the test limit');
      const message: unknown = JSON.parse(line);
      if (!message || typeof message !== 'object' || Array.isArray(message))
        throw new Error('Invalid MFA worker response');
      if ('ready' in message && message.ready === true) resolveReady();
      if ('result' in message) {
        payload = message.result;
        received = true;
      }
    } catch (error) {
      const failure = error instanceof Error ? error : new Error('Invalid MFA worker response');
      rejectReady(failure);
      rejectResult(failure);
      child.kill('SIGTERM');
    }
  });
  child.stderr.on('data', (chunk) => {
    diagnostic = (diagnostic + String(chunk)).slice(-4096);
  });
  void result.catch(() => undefined);
  return { ready, result, exit, go: () => child.stdin.end('consume\n') };
}
