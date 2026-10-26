// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { toUSVString } from 'node:util';
import { performance } from 'node:perf_hooks';
import { COMPONENTS } from '@arkenivajs/core';
import type { Logger, Telemetry, Plugin, OperationOptions } from '@arkenivajs/core';
import { SUPPORT_PLUGINS } from '@arkenivajs/core/support';
import type { ComposablePlugin, SupportPluginFactory } from '@arkenivajs/core/support';
import type {
  BarcodeSymbology,
  CodeOptions,
  CodeService,
  DataCodesPluginSettings,
  DecodedCode,
} from './contracts.js';
import type { Job } from './codec.js';
import { CodePool } from './pool.js';
import { capture, failure, integer, options, imageSnapshot } from './settings.js';
export type * from './contracts.js';

interface Observation {
  readonly logger: Logger | undefined;
  readonly telemetry: Telemetry | undefined;
}
const OBSERVATION = Symbol('codes.observation');
const observation: SupportPluginFactory = (options) => {
  const logger = options.plugins?.find((item) => item.capabilities.has('logger')),
    telemetry = options.plugins?.find((item) => item.capabilities.has('telemetry'));
  return {
    id: 'codes-observation',
    version: '0.1.0',
    capabilities: new Set(),
    dependencies: [
      ...new Set([logger?.id, telemetry?.id].filter((id): id is string => id !== undefined)),
    ],
    init(context) {
      context.provide<Observation>(OBSERVATION, {
        logger: logger ? context.require(COMPONENTS.logger) : undefined,
        telemetry: telemetry ? context.require(COMPONENTS.telemetry) : undefined,
      });
    },
    close() {},
  };
};
/** Explicit application-owned code capability. Importing the module starts no processes. */
export const CODES_CAPABILITY: unique symbol = Symbol('arkenivajs.codes');
/** Bootstrap a finite native codec pool and kill all owned native threads during shutdown. */
export function dataCodesPlugin(settings: DataCodesPluginSettings): Plugin {
  const captured = capture(settings),
    instances = new WeakMap<object, CodePool>();
  const plugin: ComposablePlugin = {
    id: 'data-barcodes',
    version: '0.1.0',
    capabilities: new Set(['codes']),
    dependencies: ['codes-observation'],
    [SUPPORT_PLUGINS]: [observation],
    async init(context) {
      const pool = new CodePool(captured),
        observers = context.require<Observation>(OBSERVATION);
      instances.set(context, pool);
      await pool.start();
      const safe = (action: () => unknown) => {
        try {
          void Promise.resolve(action()).catch(() => undefined);
        } catch {
          /* Observers cannot repeat codec work. */
        }
      };
      const run = async (job: Job, timeout: number, signal?: AbortSignal) => {
        const started = performance.now();
        let outcome = 'error',
          pixels = 0,
          bytes = 0;
        try {
          const result = await pool.run(job, timeout, signal);
          outcome = 'ok';
          pixels = result.pixels;
          bytes = result.bytes;
          return result.output;
        } finally {
          const attributes = {
              'codes.operation': job.kind,
              'codes.symbology': job.kind === 'decode' ? 'detect' : job.symbology,
              'codes.outcome': outcome,
            },
            duration = Math.max(0, performance.now() - started);
          if (observers.telemetry) {
            safe(() =>
              observers.telemetry!.recordHistogram('codes.duration.ms', duration, attributes),
            );
            safe(() => observers.telemetry!.addCounter('codes.output.bytes', bytes, attributes));
            safe(() => observers.telemetry!.addCounter('codes.image.pixels', pixels, attributes));
          }
          if (observers.logger)
            safe(() =>
              observers.logger!.debug('codes.operation.complete', {
                ...attributes,
                durationMs: duration,
                outputBytes: bytes,
                pixels,
              }),
            );
        }
      };
      const encode = async (
        text: string,
        symbology: BarcodeSymbology,
        input?: CodeOptions,
      ): Promise<Uint8Array> => {
        if (!['QR', 'CODE128', 'EAN13'].includes(symbology)) throw failure('EK_CODE_UNSUPPORTED');
        const limits = options(input, captured.defaults);
        if (typeof text !== 'string' || !text.length) throw failure('EK_CODE_DECODE');
        if (text.length > captured.maxInputBytes) throw failure('EK_CODE_LIMIT');
        if (text !== toUSVString(text)) throw failure('EK_CODE_DECODE');
        const bytes = Buffer.byteLength(text, 'utf8');
        if (bytes > captured.maxInputBytes || bytes > (symbology === 'QR' ? 2953 : 256))
          throw failure('EK_CODE_LIMIT');
        if (
          (symbology === 'CODE128' &&
            [...text].some((character) => character.charCodeAt(0) > 127)) ||
          (symbology === 'EAN13' && !/^\d{13}$/.test(text))
        )
          throw failure('EK_CODE_DECODE');
        return (await run(
          {
            kind: 'encode',
            input: text,
            symbology,
            options: limits,
            maxOutputBytes: captured.maxOutputBytes,
          },
          captured.timeoutMs,
        )) as Uint8Array;
      };
      const codes: CodeService = Object.freeze({
        generateQr(text: string, input?: CodeOptions) {
          return encode(text, 'QR', input);
        },
        generateBarcode: encode,
        async decode(image: Uint8Array, input?: CodeOptions & OperationOptions) {
          const limits = options(input, captured.defaults, true),
            timeout =
              limits.timeoutMs === undefined
                ? captured.timeoutMs
                : Math.min(captured.timeoutMs, integer(limits.timeoutMs, 1, 120000));
          const snapshot = imageSnapshot(image, captured.maxInputBytes);
          const result = (await run(
            {
              kind: 'decode',
              input: snapshot,
              symbology: 'QR',
              options: limits,
              maxOutputBytes: captured.maxOutputBytes,
            },
            timeout,
            limits.signal,
          )) as readonly DecodedCode[];
          return Object.freeze(
            result.map((item) => Object.freeze({ text: item.text, symbology: item.symbology })),
          );
        },
      });
      context.provide(CODES_CAPABILITY, codes);
    },
    async close(context) {
      await instances.get(context)?.close();
      instances.delete(context);
    },
  };
  return plugin;
}
