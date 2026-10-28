// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type WebSocket from 'ws';
import type { RawData } from 'ws';
import { TextDecoder } from 'node:util';
import { captureAbortSignal, within } from '@arkenivajs/core/support';
import type { OperationOptions } from '@arkenivajs/core';
import type { RealtimeMessage, RealtimeSession } from './contracts.js';
import type { Connection } from './runtime.js';
import { fields, name, cursor, bytes, failure, positive } from './validation.js';

function message(input: unknown, maximum: number): RealtimeMessage {
  const value = fields(input, ['channel', 'payload', 'id']);
  return Object.freeze({
    channel: name(value.channel),
    payload: bytes(value.payload, maximum),
    ...(value.id === undefined ? {} : { id: cursor(value.id) }),
  });
}
function encode(input: RealtimeMessage, maximum: number): Buffer {
  const selected = message(input, maximum);
  const frame = Buffer.from(
    JSON.stringify({
      channel: selected.channel,
      payload: Buffer.from(selected.payload).toString('base64url'),
      ...(selected.id === undefined ? {} : { id: selected.id }),
    }),
  );
  if (frame.length > maximum) throw failure('EK_REALTIME_BACKPRESSURE');
  return frame;
}
function decode(input: RawData, maximum: number): { message: RealtimeMessage; bytes: number } {
  const chunks = Array.isArray(input) ? input : [input];
  let length = 0;
  for (const chunk of chunks) {
    length += chunk instanceof ArrayBuffer ? chunk.byteLength : chunk.byteLength;
    if (length > maximum) throw failure('EK_REALTIME_BACKPRESSURE');
  }
  const frame = Buffer.concat(
    chunks.map((chunk) =>
      Buffer.from(chunk instanceof ArrayBuffer ? new Uint8Array(chunk) : chunk),
    ),
  );
  const value = fields(
    JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(frame)) as unknown,
    ['channel', 'payload', 'id'],
  );
  if (typeof value.payload !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value.payload)) throw failure();
  const payload = Buffer.from(value.payload, 'base64url');
  if (payload.toString('base64url') !== value.payload) throw failure();
  return { message: message({ ...value, payload }, maximum), bytes: length };
}
/** Attach native listeners synchronously; all application work runs behind bounded queues and current authorization. */
export function websocketSession(
  socket: WebSocket,
  connection: Connection,
): { session: RealtimeSession; deliver(message: RealtimeMessage): Promise<void> } {
  const queue: { message: RealtimeMessage; bytes: number }[] = [];
  let retained = 0,
    receiving = false,
    pendingSendBytes = 0,
    pendingSends = 0;
  let wake: (() => void) | undefined;
  const closed = () => {
    queue.length = 0;
    retained = 0;
    wake?.();
    wake = undefined;
    connection.wireClosed();
  };
  socket.once('close', closed);
  socket.on('error', () => connection.close());
  connection.attach(
    () => {
      wake?.();
      wake = undefined;
      socket.terminate();
    },
    () => socket.bufferedAmount + retained + pendingSendBytes,
  );
  const heartbeat = setInterval(() => {
    if (connection.signal.aborted || socket.readyState !== socket.OPEN) {
      clearInterval(heartbeat);
      return;
    }
    if (socket.bufferedAmount + retained + pendingSendBytes >= connection.policy.maxBufferBytes) {
      connection.close();
      return;
    }
    socket.ping();
  }, connection.policy.heartbeatMs);
  heartbeat.unref();
  socket.once('close', () => clearInterval(heartbeat));
  socket.on('message', (input) => {
    try {
      connection.check();
      const selected = decode(input, connection.inputLimit);
      if (
        retained + pendingSendBytes + socket.bufferedAmount + selected.bytes >
          connection.policy.maxBufferBytes ||
        queue.length >= 1024
      )
        throw failure('EK_REALTIME_BACKPRESSURE');
      queue.push(selected);
      retained += selected.bytes;
      connection.activity(selected.bytes, 'receive');
      wake?.();
      wake = undefined;
    } catch {
      connection.close();
    }
  });
  let sender = Promise.resolve();
  async function send(input: RealtimeMessage, options?: OperationOptions): Promise<void> {
    const data = fields(options ?? {}, ['signal', 'timeoutMs']);
    const signal = data.signal === undefined ? undefined : captureAbortSignal(data.signal);
    const timeoutMs =
      data.timeoutMs === undefined
        ? connection.operationTimeoutMs
        : positive(data.timeoutMs, connection.operationTimeoutMs);
    if (signal?.aborted) throw failure('EK_ABORTED');
    connection.check();
    const frame = encode(input, connection.outputLimit);
    if (
      pendingSends >= 1024 ||
      pendingSendBytes + retained + socket.bufferedAmount + frame.length >
        connection.policy.maxBufferBytes
    )
      throw failure('EK_REALTIME_BACKPRESSURE');
    pendingSendBytes += frame.length;
    pendingSends++;
    const actual = connection.watch(
      sender.then(async () => {
        await connection.reauthorize();
        connection.check();
        if (signal?.aborted) throw failure('EK_ABORTED');
        await new Promise<void>((resolve, reject) =>
          socket.send(frame, { binary: false, compress: false }, (error) =>
            error ? reject(failure('EK_REALTIME_CLOSED')) : resolve(),
          ),
        );
        connection.check();
        connection.activity(frame.length, 'send');
      }),
    );
    sender = actual.catch(() => undefined);
    const release = () => {
      pendingSendBytes -= frame.length;
      pendingSends--;
    };
    void actual.then(release, release);
    try {
      await within(() => actual, {
        signal: AbortSignal.any([connection.signal, ...(signal ? [signal] : [])]),
        timeoutMs,
      });
    } catch (error) {
      connection.close();
      throw error;
    }
  }
  const session: RealtimeSession = Object.freeze({
    authenticatedTenant: connection.tenant,
    signal: connection.signal,
    send,
    receive() {
      if (receiving) throw failure('EK_REALTIME_BACKPRESSURE');
      receiving = true;
      return {
        async *[Symbol.asyncIterator]() {
          try {
            while (!connection.signal.aborted) {
              if (!queue.length) {
                await connection.wait(
                  new Promise<void>((resolve) => {
                    wake = resolve;
                  }),
                );
                continue;
              }
              const value = queue.shift()!;
              retained -= value.bytes;
              await connection.reauthorize();
              connection.check();
              yield value.message;
            }
          } finally {
            receiving = false;
            connection.close();
          }
        },
      };
    },
  });
  return { session, deliver: send };
}
