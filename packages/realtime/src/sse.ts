// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { SseSource, SseSourceContext, SseEvent } from './contracts.js';
import type { Connection } from './runtime.js';
import { fields, text, name, method, cursor, failure, SseCursorError } from './validation.js';

function event(input: SseEvent, maximum: number) {
  const value = fields(input, ['id', 'type', 'data']);
  const id = cursor(value.id),
    type = name(value.type, 128),
    data = text(value.data, maximum, true);
  const lineCount = 1 + [...data].filter((c) => c === '\n').length;
  const bytes =
    Buffer.byteLength(id) + Buffer.byteLength(type) + Buffer.byteLength(data) + lineCount * 6 + 15;
  if (bytes > maximum) throw failure('EK_REALTIME_BACKPRESSURE');
  return { wire: Object.freeze({ id, event: type, data }), bytes };
}
/** Native SSE performs framing and backpressure; source validation completes before any response headers. */
export async function streamSse(connection: Connection, source: SseSource): Promise<void> {
  const { request, reply, policy } = connection;
  const header = request.headers['last-event-id'];
  const lastEventId = header === undefined ? undefined : cursor(header);
  if (lastEventId !== undefined && (source.kind !== 'durable' || !source.validateCursor))
    throw new SseCursorError('invalid');
  const context: SseSourceContext = Object.freeze({
    tenant: connection.tenant,
    signal: connection.signal,
    ...(lastEventId === undefined ? {} : { lastEventId }),
  });
  if (source.validateCursor)
    await connection.run(() => source.validateCursor!(context, connection.options()));
  await connection.reauthorize();
  connection.check();
  const iterable = source.subscribe(context);
  const iterate = method<() => AsyncIterator<SseEvent>>(iterable, Symbol.asyncIterator)!;
  const iterator = iterate(),
    next = method<() => Promise<IteratorResult<SseEvent>>>(iterator, 'next')!,
    finish = method<() => Promise<IteratorResult<SseEvent>>>(iterator, 'return', false);
  reply.header('cache-control', 'no-store');
  reply.header('referrer-policy', 'no-referrer');
  reply.header('x-content-type-options', 'nosniff');
  connection.attach(
    (force) => {
      reply.sse.close();
      if (force && reply.raw.headersSent && !reply.raw.writableFinished) reply.raw.destroy();
    },
    () => reply.raw.writableLength,
  );
  reply.sse.onClose(() => connection.close());
  try {
    reply.sse.sendHeaders();
    while (!connection.signal.aborted) {
      const pending = connection.watch(Promise.resolve().then(next));
      const result = fields(await connection.wait(pending), ['done', 'value']);
      if (typeof result.done !== 'boolean') throw failure('EK_BACKEND_UNAVAILABLE');
      if (result.done) break;
      await connection.reauthorize();
      const selected = event(
        result.value as SseEvent,
        Math.min(connection.outputLimit, policy.maxBufferBytes),
      );
      if (reply.raw.writableLength + selected.bytes > policy.maxBufferBytes)
        throw failure('EK_REALTIME_BACKPRESSURE');
      const sent = connection.watch(reply.sse.send(selected.wire));
      await connection.wait(sent);
      connection.check();
      connection.activity(selected.bytes, 'send');
    }
  } finally {
    if (finish)
      connection.retainCleanup(
        Promise.resolve()
          .then(finish)
          .then((result) => {
            if (!result || typeof result !== 'object' || result.done !== true)
              throw failure('EK_BACKEND_UNAVAILABLE');
          }),
      );
    connection.close(false);
  }
}
