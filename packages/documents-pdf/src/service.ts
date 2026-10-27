// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  PdfService,
  PdfBuilder,
  PdfLimits,
  PdfTextSpec,
  PdfInfo,
  PdfTextPage,
} from './contracts.js';
import type { OperationOptions } from '@arkenivajs/core';
import { performance } from 'node:perf_hooks';
import type { Settings } from './settings.js';
import type { Work } from './backend.js';
import { limits, limitNames, spec } from './settings.js';
import { fields, array, bytes, failure } from './validation.js';
import { operation, Request } from './runtime.js';
import { recorder } from './observation.js';
import type { Observers } from './observation.js';

function call(
  input: (PdfLimits & OperationOptions) | undefined,
  settings: Settings,
  runtime = true,
) {
  const value = fields(input ?? {}, [...limitNames, ...(runtime ? ['signal', 'timeoutMs'] : [])]),
    merged: Record<string, unknown> = { ...settings.defaults };
  for (const key of limitNames) if (value[key] !== undefined) merged[key] = value[key];
  const policy = limits(merged as PdfLimits),
    maximum = Math.min(settings.timeoutMs, policy.maxDecodeMs);
  const requested = operation(
    {
      ...(value.signal === undefined ? {} : { signal: value.signal as AbortSignal }),
      ...(value.timeoutMs === undefined ? {} : { timeoutMs: value.timeoutMs as number }),
    },
    maximum,
  );
  return {
    policy,
    requested: {
      timeoutMs: requested.timeoutMs,
      ...(requested.signal ? { signal: requested.signal } : {}),
    },
  };
}
function inputs(
  raw: readonly Uint8Array[],
  policy: ReturnType<typeof limits>,
  settings: Settings,
): readonly Uint8Array[] {
  const result: Uint8Array[] = [];
  let total = 0;
  try {
    const source = array(raw, 128);
    if (!source.length) throw failure();
    for (const item of source) {
      const owned = bytes(item, Math.min(policy.maxBytes, settings.maxInputBytes - total));
      result.push(owned);
      total += owned.length;
      if (!owned.length) throw failure();
    }
    return result;
  } catch (error) {
    for (const value of result) value.fill(0);
    throw error;
  }
}
function immutable<T>(value: T): T {
  if (value && typeof value === 'object' && !(value instanceof Uint8Array)) {
    for (const item of Object.values(value)) immutable(item);
    Object.freeze(value);
  }
  return value;
}
export function managedService(
  settings: Settings,
  applicationSignal: AbortSignal,
  ready: () => boolean,
  observers: Observers = {},
) {
  const active = new Set<Request>(),
    observe = recorder(observers);
  let closed = false;
  const check = () => {
    if (closed || applicationSignal.aborted || !ready()) throw failure('EK_RESOURCE_CLOSED');
  };
  const launch = async (work: Work, requested: OperationOptions): Promise<unknown> => {
    const started = performance.now();
    const inputBytes = work.inputs.reduce((total, value) => total + value.length, 0);
    let task: Request | undefined;
    try {
      check();
      if (active.size >= settings.maxConcurrent) throw failure('EK_PDF_LIMIT');
      task = new Request(settings, work, requested, applicationSignal, (value) => {
        observe.measure('worker.memory.sampled-peak.bytes', value.memoryBytes);
        observe.measure('native.duration.ms', value.durationMs);
        observe.measure('native.cpu.ms', value.cpuMs);
        if (value.durationMs > 0)
          observe.measure('pages.per.second', (value.pages * 1000) / value.durationMs);
      });
      active.add(task);
      const owned = task;
      void task.done.finally(() => active.delete(owned));
      const value = await task.result;
      if (value instanceof Uint8Array) {
        if (value.byteLength > work.maximum) throw failure('EK_PDF_LIMIT');
        observe.measure('output.bytes', value.byteLength);
        observe.measure('input.bytes', inputBytes);
        observe.complete(work.operation, 'ok', performance.now() - started);
        return value;
      }
      if (Buffer.byteLength(JSON.stringify(value)) > work.maximum) throw failure('EK_PDF_LIMIT');
      observe.measure('input.bytes', inputBytes);
      observe.complete(work.operation, 'ok', performance.now() - started);
      return immutable(value);
    } catch (error) {
      observe.complete(work.operation, 'error', performance.now() - started);
      throw error;
    } finally {
      if (!task) for (const value of work.inputs) value.fill(0);
    }
  };
  const work = (
    operation: Work['operation'],
    captured: ReturnType<typeof call>,
    source: readonly Uint8Array[],
    specs: Work['specs'] = [],
  ): Work => ({
    operation,
    limits: captured.policy,
    maximum: Math.min(settings.maxOutputBytes, captured.policy.maxBytes),
    inputs: inputs(source, captured.policy, settings),
    specs,
    fonts: {},
  });
  const service = Object.freeze<PdfService>({
    create(requested) {
      check();
      const captured = call(requested, settings, false),
        commands: Readonly<Required<PdfTextSpec>>[] = [];
      let total = 0,
        busy = false;
      return Object.freeze<PdfBuilder>({
        addText(text, page, x, y, options) {
          check();
          if (busy) throw failure('EK_PDF_LIMIT');
          const appearance = fields(options, ['font', 'size', 'colorHex']),
            command = spec(
              {
                text,
                page,
                x,
                y,
                font: appearance.font as string,
                size: appearance.size as number,
                colorHex: appearance.colorHex as string,
              },
              settings,
              captured.policy,
            );
          const size = Buffer.byteLength(command.text) + Buffer.byteLength(command.font) + 128;
          if (
            commands.length >= captured.policy.maxTextItems ||
            total + size > captured.policy.maxBytes
          )
            throw failure('EK_PDF_LIMIT');
          commands.push(command);
          total += size;
        },
        async save(requestedOperation) {
          check();
          if (busy) throw failure('EK_PDF_LIMIT');
          const runtime = operation(
            requestedOperation,
            Math.min(settings.timeoutMs, captured.policy.maxDecodeMs),
          );
          busy = true;
          try {
            return (await launch(
              {
                operation: 'create',
                limits: captured.policy,
                maximum: Math.min(settings.maxOutputBytes, captured.policy.maxBytes),
                inputs: [],
                specs: [...commands],
                fonts: {},
              },
              {
                timeoutMs: runtime.timeoutMs,
                ...(runtime.signal ? { signal: runtime.signal } : {}),
              },
            )) as Uint8Array;
          } finally {
            busy = false;
          }
        },
      });
    },
    async inspect(source, requested) {
      check();
      const captured = call(requested, settings);
      return (await launch(work('inspect', captured, [source]), captured.requested)) as PdfInfo;
    },
    async extractText(source, requested) {
      check();
      const captured = call(requested, settings);
      return (await launch(
        work('extract', captured, [source]),
        captured.requested,
      )) as readonly PdfTextPage[];
    },
    async merge(source, requested) {
      check();
      const captured = call(requested, settings);
      return (await launch(work('merge', captured, source), captured.requested)) as Uint8Array;
    },
    async addText(source, requestedSpec, requested) {
      check();
      const captured = call(requested, settings),
        command = spec(requestedSpec, settings, captured.policy);
      return (await launch(
        work('add', captured, [source], [command]),
        captured.requested,
      )) as Uint8Array;
    },
  });
  return {
    service,
    async close() {
      closed = true;
      for (const task of active) task.stop('EK_ABORTED');
      await Promise.all([...active].map((task) => task.done));
    },
  };
}
