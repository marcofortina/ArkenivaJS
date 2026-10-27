// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { XmlService, XmlOptions } from './contracts.js';
import { Runtime, operation } from './runtime.js';
import { options, optionKeys } from './settings.js';
import { fields, failure } from './validation.js';
import { documentSnapshot, inputText } from './backend.js';
import type { Xsd } from './xsd.js';

export function service(runtime: Runtime, xsd?: Xsd): XmlService {
  return Object.freeze<XmlService>({
    async parse(input, requested) {
      runtime.check();
      const value = fields(requested === undefined ? {} : requested, [
        ...optionKeys,
        'signal',
        'timeoutMs',
      ]);
      const { signal, timeoutMs, ...codec } = value;
      const call = operation(
        {
          ...(signal === undefined ? {} : { signal: signal as AbortSignal }),
          ...(timeoutMs === undefined ? {} : { timeoutMs: timeoutMs as number }),
        },
        runtime.settings.timeoutMs,
      );
      if (call.signal?.aborted) throw failure('EK_ABORTED');
      const policy = options(codec as XmlOptions, runtime.settings.defaults),
        text = inputText(input, Math.min(policy.maxBytes, runtime.settings.maxInputBytes));
      return runtime.execute('parse', text, policy, call);
    },
    async stringify(input, requested) {
      runtime.check();
      const policy = options(requested, runtime.settings.defaults),
        captured = documentSnapshot(input, {
          ...policy,
          maxBytes: Math.min(policy.maxBytes, runtime.settings.maxInputBytes),
        });
      return runtime.execute('stringify', captured, policy);
    },
    async validateXsd(input, schemaId, requested) {
      runtime.check();
      const call = operation(requested, runtime.settings.timeoutMs);
      if (call.signal?.aborted) throw failure('EK_ABORTED');
      if (!(input instanceof Uint8Array)) throw failure('EK_XML_PARSE');
      const text = inputText(
        input,
        Math.min(runtime.settings.defaults.maxBytes, runtime.settings.maxInputBytes),
      );
      if (typeof schemaId !== 'string' || !Object.hasOwn(runtime.settings.schemas, schemaId))
        throw failure('EK_XML_SCHEMA');
      if (!xsd) throw failure('EK_UNSUPPORTED_CAPABILITY');
      return xsd.validate(text, schemaId, call);
    },
  });
}
