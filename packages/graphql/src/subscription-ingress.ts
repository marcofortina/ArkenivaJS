// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TextDecoder, types } from 'node:util';
import { MessageType, parseMessage } from 'graphql-ws';
import type { Message } from 'graphql-ws';
import type WebSocket from 'ws';
import { KitError } from '@arkenivajs/core';
import type { CapturedSettings } from './policy.js';
import { failure, record } from './policy.js';
import { operationInput } from './input.js';

type Limits = CapturedSettings['security']['limits'];

/** Decode the approved standard dialect before native subscription parsing or context merging. */
export function subscriptionFrame(raw: unknown, binary: boolean, limits: Limits): Message {
  const maximum = Math.min(
    Number.MAX_SAFE_INTEGER,
    limits.maxDocumentBytes * 6 + limits.maxVariablesBytes * 6 + 8192,
  );
  if (!Buffer.isBuffer(raw) || binary) throw failure('EK_GQL_SUBSCRIPTION');
  if (raw.byteLength > maximum) throw failure('EK_GQL_INPUT_LIMIT');
  let message: Message;
  try {
    message = parseMessage(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    record(message, ['type', 'id', 'payload']);
  } catch {
    throw failure('EK_GQL_SUBSCRIPTION');
  }
  switch (message.type) {
    case MessageType.ConnectionInit: {
      let payload;
      try {
        payload = record(message.payload, ['authorization']);
      } catch {
        throw failure('EK_GQL_AUTH');
      }
      if (
        typeof payload.authorization !== 'string' ||
        !payload.authorization.trim() ||
        Buffer.byteLength(payload.authorization) > 8192 ||
        /[^\x20-\x7e]/.test(payload.authorization)
      )
        throw failure('EK_GQL_AUTH');
      break;
    }
    case MessageType.Subscribe:
      operationInput(message.payload, limits, 'WEBSOCKET');
      break;
    case MessageType.Complete:
      break;
    case MessageType.Ping:
    case MessageType.Pong:
      if (raw.byteLength > 1024) throw failure('EK_GQL_INPUT_LIMIT');
      break;
    default:
      throw failure('EK_GQL_SUBSCRIPTION');
  }
  if ('id' in message && Buffer.byteLength(message.id) > 256) throw failure('EK_GQL_INPUT_LIMIT');
  return message;
}

/** Filter before the native events iterator can enqueue a frame; the owner admits work synchronously. */
export function installSubscriptionIngress(
  socket: WebSocket,
  limits: Limits,
  admit: (frame: Message) => undefined,
) {
  const emit = socket.emit.bind(socket);
  let closed = false;
  socket.once('close', () => {
    closed = true;
  });
  socket.emit = (event, ...args: unknown[]) => {
    if (event === 'message') {
      if (closed) return false;
      try {
        const frame = subscriptionFrame(args[0], args[1] === true, limits);
        const result: unknown = admit(frame);
        if (result !== undefined) {
          if (types.isPromise(result)) void result.catch(() => undefined);
          throw failure('EK_GQL_SUBSCRIPTION');
        }
      } catch (error) {
        closed = true;
        const code =
          error instanceof KitError &&
          [
            'EK_GQL_INPUT_LIMIT',
            'EK_GQL_VALIDATION',
            'EK_GQL_AUTH',
            'EK_GQL_FORBIDDEN',
            'EK_GQL_COMPLEXITY',
            'EK_GQL_BACKPRESSURE',
          ].includes(error.code)
            ? error.code
            : 'EK_GQL_SUBSCRIPTION';
        socket.close(code === 'EK_GQL_AUTH' ? 4401 : 4400, code);
        return false;
      }
    }
    return emit(event, ...args);
  };
}
