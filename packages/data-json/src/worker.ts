// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import { KitError } from '@arkenivajs/core';
import { parse, stringify } from './codec.js';
import { Schemas } from './schemas.js';
import { Mappings } from './mappings.js';
import { errorCodes, headerBytes } from './protocol.js';
import type { Request } from './protocol.js';
import type { Settings } from './settings.js';
import { failure } from './validation.js';

const { settings, buffer } = workerData as { settings: Settings; buffer: SharedArrayBuffer };
const header = new Int32Array(buffer, 0, 4),
  output = new Uint8Array(buffer, headerBytes);
try {
  const schemas = new Schemas(settings.schemas),
    mappings = new Mappings(settings.mappings, schemas);
  parentPort!.on('message', (request: Request) => {
    const deadline = performance.now() + request.timeoutMs;
    const check = () => {
      if (performance.now() > deadline) throw failure('EK_TIMEOUT');
    };
    try {
      check();
      const limits = {
        ...request.limits,
        maxBytes: Math.min(request.limits.maxBytes, settings.maxInputBytes),
      };
      let result: string;
      if (request.operation === 'parse')
        result = stringify(
          parse(request.text, limits, check),
          {
            ...request.limits,
            maxBytes: settings.maxOutputBytes,
            indentSpaces: 0,
          },
          check,
        );
      else {
        const value = parse(request.text, limits, check);
        if (request.operation === 'stringify') result = stringify(value, request.limits, check);
        else if (request.operation === 'transform')
          result = stringify(
            mappings.transform(value, request.id!, check),
            {
              maxBytes: settings.maxOutputBytes,
              maxDepth: request.limits.maxDepth,
              indentSpaces: 0,
            },
            check,
          );
        else result = JSON.stringify(schemas.validate(value, request.id!));
      }
      check();
      const bytes = Buffer.from(result, 'utf8');
      if (bytes.length > output.length) throw failure('EK_JSON_PARSE');
      output.set(bytes);
      Atomics.store(header, 1, bytes.length);
      Atomics.store(header, 3, process.memoryUsage().heapUsed);
      Atomics.store(header, 0, 1);
    } catch (error) {
      const found = error instanceof KitError ? errorCodes.indexOf(error.code) : -1;
      Atomics.store(header, 2, found < 0 ? 0 : found);
      Atomics.store(header, 0, 2);
    } finally {
      Atomics.notify(header, 0);
    }
  });
  parentPort!.postMessage({ ready: true });
} catch (error) {
  const code =
    error instanceof KitError && errorCodes.includes(error.code)
      ? error.code
      : 'EK_BACKEND_UNAVAILABLE';
  parentPort!.postMessage({ ready: false, code });
  parentPort!.close();
}
