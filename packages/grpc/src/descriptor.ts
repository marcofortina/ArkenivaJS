// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { Worker } from 'node:worker_threads';
import { fromJSON } from '@grpc/proto-loader';
import type { PackageDefinition } from '@grpc/proto-loader';
import type { INamespace } from 'protobufjs';
import protobuf from 'protobufjs';
import { Client } from '@grpc/grpc-js';
import { failure } from './errors.js';

const forbidden = new Set(['__proto__', 'prototype', 'constructor']);
const nativeMethods = new Set<string>();
for (
  let current: object | null = Client.prototype;
  current;
  current = Object.getPrototypeOf(current) as object | null
)
  for (const key of Object.getOwnPropertyNames(current)) nativeMethods.add(key);
const messages = new WeakMap<
  object,
  Readonly<{ request: protobuf.Type; response: protobuf.Type }>
>();
export function messageTypes(method: object) {
  const types = messages.get(method);
  if (!types) throw failure('EK_CONFIG_INVALID');
  return types;
}
function inspect(value: unknown, depth = 0, budget = { entries: 0 }): void {
  if (depth > 64 || ++budget.entries > 32768) throw failure('EK_CONFIG_INVALID');
  if (value === null || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (forbidden.has(key)) throw failure('EK_CONFIG_INVALID');
    inspect(child, depth + 1, budget);
  }
}

/** No native loader receives filesystem access, URL resolution or a live mutable descriptor. */
export async function loadDescriptor(
  entry: string,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<PackageDefinition> {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000)
    throw failure('EK_CONFIG_INVALID');
  if (signal.aborted) throw failure('EK_ABORTED');
  const worker = new Worker(new URL('./descriptor-worker.js', import.meta.url), {
    workerData: { entry },
    execArgv: [],
    env: { TZ: 'UTC' },
    stdout: true,
    stderr: true,
    resourceLimits: { maxOldGenerationSizeMb: 96, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
  });
  worker.stdout.resume();
  worker.stderr.resume();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort: () => void = () => undefined;
  try {
    const schema = await new Promise<INamespace>((resolve, reject) => {
      abort = () => reject(failure('EK_ABORTED'));
      signal.addEventListener('abort', abort, { once: true });
      timer = setTimeout(() => reject(failure('EK_GRPC_DEADLINE')), timeoutMs);
      worker.once('error', () => reject(failure('EK_CONFIG_INVALID')));
      worker.once('exit', () => reject(failure('EK_CONFIG_INVALID')));
      worker.once('message', (message: unknown) => {
        try {
          if (
            !message ||
            typeof message !== 'object' ||
            !('ok' in message) ||
            message.ok !== true ||
            !('schema' in message)
          )
            throw failure('EK_CONFIG_INVALID');
          inspect(message.schema);
          if (signal.aborted) throw failure('EK_ABORTED');
          resolve(message.schema as INamespace);
        } catch {
          reject(failure(signal.aborted ? 'EK_ABORTED' : 'EK_CONFIG_INVALID'));
        }
      });
      if (signal.aborted) abort();
    });
    const definition = fromJSON(schema, {
      keepCase: true,
      longs: String,
      enums: String,
      bytes: Buffer,
      defaults: false,
      oneofs: true,
    });
    const reflection = protobuf.Root.fromJSON(schema).resolveAll();
    for (const [serviceName, service] of Object.entries(definition)) {
      if ('format' in service) continue;
      const reflected = reflection.lookupService(serviceName);
      for (const [name, method] of Object.entries(service)) {
        if (
          nativeMethods.has(name) ||
          (method.originalName && nativeMethods.has(method.originalName))
        )
          throw failure('EK_CONFIG_INVALID');
        const native = reflected.methods[name];
        native?.resolve();
        if (!native?.resolvedRequestType || !native.resolvedResponseType)
          throw failure('EK_CONFIG_INVALID');
        messages.set(
          method,
          Object.freeze({
            request: native.resolvedRequestType,
            response: native.resolvedResponseType,
          }),
        );
      }
    }
    return definition;
  } finally {
    if (timer) clearTimeout(timer);
    signal.removeEventListener('abort', abort);
    await worker.terminate();
  }
}
