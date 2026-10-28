// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { IncomingHttpHeaders } from 'node:http';
import type { Telemetry } from '@arkenivajs/core';

type ContextualTelemetry = Telemetry & {
  traceHeaders?: () => Readonly<{ traceparent?: string; tracestate?: string }>;
  withRemoteContext?: <T>(
    headers: Readonly<Record<string, string | undefined>>,
    work: () => T,
  ) => T;
};
function carrier(input: IncomingHttpHeaders): Record<string, string> {
  const result: Record<string, string> = {};
  for (const key of ['traceparent', 'tracestate']) {
    const value = input[key];
    if (typeof value === 'string' && value.length <= 512 && /^[\x20-\x7e]+$/.test(value))
      result[key] = value;
  }
  return result;
}
/** A remote diagnostic context never supplies trusted identity or baggage. */
export function remoteTrace<T>(
  telemetry: Telemetry | undefined,
  headers: IncomingHttpHeaders,
  work: () => Promise<T>,
): Promise<T> {
  let task: Promise<T> | undefined;
  const invoke = () => (task ??= Promise.resolve().then(work));
  try {
    void Promise.resolve(
      (telemetry as ContextualTelemetry | undefined)?.withRemoteContext?.(carrier(headers), invoke),
    ).catch(() => undefined);
  } catch {
    /* Diagnostic failure cannot replay the forwarding operation. */
  }
  return invoke();
}
/** Only the current locally established client span may populate outbound diagnostic headers. */
export function injectTrace(telemetry: Telemetry | undefined, headers: IncomingHttpHeaders): void {
  try {
    Object.assign(
      headers,
      carrier((telemetry as ContextualTelemetry | undefined)?.traceHeaders?.() ?? {}),
    );
  } catch {
    /* Diagnostic failure cannot change forwarding or authorization. */
  }
}
