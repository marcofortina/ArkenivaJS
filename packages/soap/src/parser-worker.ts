// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import { serialize } from 'node:v8';
import { KitError } from '@arkenivajs/core';
import { nativeWsdl } from './backend.js';
import { inspectXml } from './xml.js';
import { errorCodes, headerBytes } from './protocol.js';
import type { ParserSettings } from './protocol.js';
import { failure } from './validation.js';

const { settings, buffer } = workerData as {
  settings: ParserSettings;
  buffer: SharedArrayBuffer;
};
const header = new Int32Array(buffer, 0, 4),
  output = new Uint8Array(buffer, headerBytes);
try {
  const contract = await nativeWsdl(settings.source);
  parentPort!.on('message', (source: string) => {
    try {
      let root;
      try {
        root = inspectXml(source, settings.maxBytes).root;
      } catch {
        throw failure('EK_SOAP_SCHEMA');
      }
      const namespace =
        settings.protocol === '1.1'
          ? 'http://schemas.xmlsoap.org/soap/envelope/'
          : 'http://www.w3.org/2003/05/soap-envelope';
      if (root.local !== 'Envelope' || root.uri !== namespace) throw failure('EK_SOAP_SCHEMA');
      let result: unknown;
      try {
        result = contract.xmlToObject(source);
      } catch (error) {
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
