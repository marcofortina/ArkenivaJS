// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { spawn, execFile } from 'node:child_process';
import { promisify, types } from 'node:util';
import { realpath, access } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { serialize, deserialize } from 'node:v8';

const supervisor = fileURLToPath(new URL('./supervised-resources.py', import.meta.url)),
  bridge = fileURLToPath(new URL('./supervised-bridge.mjs', import.meta.url)),
  environment = { LANG: 'C.UTF-8', TZ: 'UTC', NODE_ENV: 'test' },
  aborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get,
  signalPrototype = Object.getPrototypeOf(AbortSignal.prototype),
  addAbortListener = signalPrototype.addEventListener,
  removeAbortListener = signalPrototype.removeEventListener;
const failure = (code) =>
  Object.assign(new Error('The supervised benchmark worker did not complete safely'), { code });
const integer = (value, minimum, maximum) =>
  Number.isSafeInteger(value) && value >= minimum && value <= maximum;

/** Internal Linux benchmark utility; resources cover the complete supervised lifecycle. */
export async function runSupervisedWorker(worker, input, options = {}) {
  const allowed = ['timeoutMs', 'cleanupGraceMs', 'sampleIntervalMs', 'maxMessageBytes', 'signal'];
  if (!options || typeof options !== 'object' || types.isProxy(options) || Array.isArray(options))
    throw failure('ERR_BENCHMARK_POLICY');
  const captured = Object.create(null);
  for (const key of Reflect.ownKeys(options)) {
    const descriptor = Object.getOwnPropertyDescriptor(options, key);
    if (!allowed.includes(key) || !descriptor || !('value' in descriptor))
      throw failure('ERR_BENCHMARK_POLICY');
    captured[key] = descriptor.value;
  }
  const timeoutMs = captured.timeoutMs === undefined ? 30000 : captured.timeoutMs,
    cleanupGraceMs = captured.cleanupGraceMs === undefined ? 100 : captured.cleanupGraceMs,
    sampleIntervalMs = captured.sampleIntervalMs === undefined ? 20 : captured.sampleIntervalMs,
    maxMessageBytes = captured.maxMessageBytes === undefined ? 1048576 : captured.maxMessageBytes,
    signal = captured.signal;
  if (
    !integer(timeoutMs, 1, 120000) ||
    !integer(cleanupGraceMs, 1, 1000) ||
    !integer(sampleIntervalMs, 5, 250) ||
    !integer(maxMessageBytes, 64, 1048576) ||
    Math.ceil((timeoutMs + cleanupGraceMs + 3000) / sampleIntervalMs) > 10000
  )
    throw failure('ERR_BENCHMARK_POLICY');
  try {
    if (types.isProxy(signal)) throw failure('ERR_BENCHMARK_POLICY');
    if (signal !== undefined && aborted.call(signal)) throw failure('ERR_BENCHMARK_ABORTED');
  } catch (error) {
    if (error.code === 'ERR_BENCHMARK_ABORTED') throw error;
    throw failure('ERR_BENCHMARK_POLICY');
  }
  if (process.platform !== 'linux') throw failure('ERR_BENCHMARK_UNSUPPORTED');
  let serialized, path;
  try {
    const supplied = worker instanceof URL ? fileURLToPath(worker) : worker;
    if (typeof supplied !== 'string' || !isAbsolute(supplied)) throw new Error();
    path = await realpath(supplied);
    serialized = serialize(input);
    if (serialized.length > maxMessageBytes) throw new Error();
  } catch {
    throw failure('ERR_BENCHMARK_POLICY');
  }
  if (signal !== undefined && aborted.call(signal)) throw failure('ERR_BENCHMARK_ABORTED');
  try {
    await access('/proc/self/smaps_rollup');
    const probe = await promisify(execFile)('/usr/bin/python3', [supervisor, '--probe'], {
      env: environment,
      timeout: 2000,
      maxBuffer: 4096,
    });
    if (probe.stderr || JSON.parse(probe.stdout).supported !== true) throw new Error();
  } catch {
    throw failure('ERR_BENCHMARK_UNSUPPORTED');
  }
  if (signal !== undefined && aborted.call(signal)) throw failure('ERR_BENCHMARK_ABORTED');
  const config = JSON.stringify({
    node: process.execPath,
    bridge,
    worker: path,
    inputBase64: serialized.toString('base64'),
    timeoutMs,
    cleanupGraceMs,
    sampleIntervalMs,
    maxMessageBytes,
  });
  return new Promise((resolve, reject) => {
    let child;
    let output = '',
      outputBytes = 0,
      errorBytes = 0,
      invalid = false,
      cancelled = false;
    const cancel = () => {
      cancelled = true;
      child?.kill('SIGTERM');
    };
    try {
      if (signal !== undefined) addAbortListener.call(signal, 'abort', cancel, { once: true });
      if (signal !== undefined && aborted.call(signal)) {
        removeAbortListener.call(signal, 'abort', cancel);
        reject(failure('ERR_BENCHMARK_ABORTED'));
        return;
      }
    } catch {
      reject(failure('ERR_BENCHMARK_POLICY'));
      return;
    }
    try {
      child = spawn('/usr/bin/python3', [supervisor], {
        env: environment,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch {
      if (signal !== undefined) removeAbortListener.call(signal, 'abort', cancel);
      reject(failure('ERR_BENCHMARK_SUPERVISOR'));
      return;
    }
    const watchdog = setTimeout(
      () => {
        invalid = true;
        child.kill('SIGTERM');
      },
      timeoutMs + cleanupGraceMs + 4000,
    );
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      outputBytes += Buffer.byteLength(chunk);
      if (outputBytes > 3145728) {
        invalid = true;
        child.kill('SIGTERM');
      } else output += chunk;
    });
    // Untrusted worker stderr is ignored by the Node bridge; supervisor stderr is never relayed.
    child.stderr.on('data', (chunk) => {
      errorBytes += chunk.length;
      if (errorBytes > 65536) child.kill('SIGTERM');
    });
    child.on('error', () => {
      invalid = true;
    });
    child.stdin.on('error', () => {
      invalid = true;
    });
    child.once('close', (code) => {
      clearTimeout(watchdog);
      if (signal !== undefined) removeAbortListener.call(signal, 'abort', cancel);
      try {
        // Before its SIGTERM handler is installed, Python has not created a Node child.
        if (cancelled && outputBytes === 0 && child.signalCode === 'SIGTERM')
          throw failure('ERR_BENCHMARK_ABORTED');
        if (invalid || code !== 0 || errorBytes) throw failure('ERR_BENCHMARK_SUPERVISOR');
        const report = JSON.parse(output);
        if (!report.resource.allChildrenWaited || report.resource.remainingOwnedProcesses !== 0)
          throw failure('ERR_BENCHMARK_SUPERVISOR');
        if (cancelled || report.status !== 'completed') {
          const error = failure(
            cancelled
              ? 'ERR_BENCHMARK_ABORTED'
              : report.status === 'timeout'
                ? 'ERR_BENCHMARK_TIMEOUT'
                : 'ERR_BENCHMARK_WORKER',
          );
          Object.defineProperty(error, 'resource', { value: Object.freeze(report.resource) });
          throw error;
        }
        const encoded = Buffer.from(report.resultBase64, 'base64');
        if (encoded.length > maxMessageBytes) throw failure('ERR_BENCHMARK_SUPERVISOR');
        resolve({ message: deserialize(encoded), resource: Object.freeze(report.resource) });
      } catch (error) {
        reject(
          typeof error?.code === 'string' && error.code.startsWith('ERR_BENCHMARK_')
            ? error
            : failure('ERR_BENCHMARK_SUPERVISOR'),
        );
      }
    });
    child.stdin.end(config);
    if (signal && aborted.call(signal)) cancel();
  });
}
