// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import { serialize } from 'node:v8';
import { types } from 'node:util';
import { KitError } from '@arkenivajs/core';
import { nativeWsdl, nativeGraph } from './backend.js';
import { inspectEnvelope } from './envelope.js';
import type { QualifiedName } from './catalog.js';
import { errorCodes, headerBytes } from './protocol.js';
import type { ParserSettings } from './protocol.js';
import { failure } from './validation.js';
import { verifyBackend } from './backend-probe.js';

const { settings, buffer } = workerData as {
  settings: ParserSettings;
  buffer: SharedArrayBuffer;
};
const header = new Int32Array(buffer, 0, 4),
  output = new Uint8Array(buffer, headerBytes);
function checked(value: unknown): void {
  const active = new Set<object>();
  let nodes = 0;
  function visit(value: unknown, depth: number) {
    if (++nodes > 20000 || depth > 64 || (typeof value === 'number' && !Number.isFinite(value)))
      throw failure('EK_SOAP_SCHEMA');
    if (!value || typeof value !== 'object') return;
    if (types.isDate(value)) {
      if (!Number.isFinite(Date.prototype.getTime.call(value))) throw failure('EK_SOAP_SCHEMA');
      return;
    }
    if (active.has(value)) throw failure('EK_UNSUPPORTED_CAPABILITY');
    active.add(value);
    for (const entry of Object.values(value)) visit(entry, depth + 1);
    active.delete(value);
  }
  visit(value, 0);
}
try {
  await verifyBackend();
  const contract = settings.assets
    ? await nativeGraph(settings.assets, true)
    : await nativeWsdl(settings.source, true);
  parentPort!.on(
    'message',
    ({ source, expected }: { source: string; expected?: readonly QualifiedName[] }) => {
      try {
        inspectEnvelope(source, settings.protocol, settings.maxBytes, expected);
        let result: unknown;
        try {
          result = contract.xmlToObject(source);
        } catch (error) {
          if (
            error instanceof KitError &&
            ['EK_SOAP_SCHEMA', 'EK_UNSUPPORTED_CAPABILITY'].includes(error.code)
          )
            throw error;
          const fault =
            error &&
            typeof error === 'object' &&
            'root' in error &&
            error.root &&
            typeof error.root === 'object' &&
            'Envelope' in error.root &&
            error.root.Envelope &&
            typeof error.root.Envelope === 'object' &&
            'Body' in error.root.Envelope &&
            error.root.Envelope.Body &&
            typeof error.root.Envelope.Body === 'object' &&
            Object.hasOwn(error.root.Envelope.Body, 'Fault');
          throw failure(fault ? 'EK_SOAP_FAULT' : 'EK_SOAP_SCHEMA');
        }
        checked(result);
        const bytes = serialize(result);
        if (bytes.length > output.length) throw failure('EK_SOAP_SCHEMA');
        output.set(bytes);
        Atomics.store(header, 1, bytes.length);
        Atomics.store(header, 0, 1);
      } catch (error) {
        const code = error instanceof KitError ? errorCodes.indexOf(error.code) : -1;
        Atomics.store(header, 2, code < 0 ? 0 : code);
        Atomics.store(header, 0, 2);
      } finally {
        Atomics.notify(header, 0);
      }
    },
  );
  parentPort!.postMessage({ ready: true });
} catch (error) {
  const code =
    error instanceof KitError && errorCodes.includes(error.code)
      ? error.code
      : 'EK_BACKEND_UNAVAILABLE';
  parentPort!.postMessage({ ready: false, code });
  parentPort!.close();
}
