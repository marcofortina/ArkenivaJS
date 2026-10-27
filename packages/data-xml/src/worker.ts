// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import { KitError } from '@arkenivajs/core';
import { parseNative, stringifyNative, preflight, schemaDependencies } from './backend.js';
import type { XmlDocument } from './contracts.js';
import type { options } from './settings.js';
const request = workerData as {
  command: 'parse' | 'stringify' | 'xsd-guard' | 'xsd-schema';
  input: string | XmlDocument;
  policy: ReturnType<typeof options>;
  maxOutputBytes: number;
};
try {
  if (request.command === 'xsd-guard') preflight(request.input as string, request.policy, true);
  const value =
    request.command === 'xsd-schema'
      ? JSON.stringify(schemaDependencies(request.input as string, request.policy))
      : request.command === 'xsd-guard'
        ? 'validated-xml-syntax'
        : request.command === 'parse'
          ? parseNative(request.input as string, request.policy)
          : stringifyNative(request.input as XmlDocument, request.policy);
  if (
    Buffer.byteLength(typeof value === 'string' ? value : JSON.stringify(value)) >
    request.maxOutputBytes
  )
    throw new Error('The XML output exceeds its configured bound');
  parentPort?.postMessage({ value, heapBytes: process.memoryUsage().heapUsed });
} catch (error) {
  parentPort?.postMessage({ error: error instanceof KitError ? error.code : 'EK_XML_SECURITY' });
} finally {
  parentPort?.close();
}
