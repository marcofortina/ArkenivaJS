// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { MessageType, parseMessage } from 'graphql-ws';
import type { Message } from 'graphql-ws';
import type WebSocket from 'ws';
import { failure } from './policy.js';
import { subscriptionError } from './subscription-output.js';

interface Bounds {
  readonly maxResultBytes: number;
  readonly maxQueuedEvents: number;
  readonly timeoutMs: number;
}

/** The native engine owns the dialect; this adapter owns finite physical writes and safe errors. */
export class SubscriptionEgress {
  private readonly writes = new Set<(error?: Error) => void>();
  private closed = false;
  private readonly maximum: number;
  private readonly bufferedMaximum: number;

  constructor(
    private readonly socket: WebSocket,
    bounds: Bounds,
    private readonly sent: (message: Message) => void,
  ) {
    for (const value of [bounds.maxResultBytes, bounds.maxQueuedEvents, bounds.timeoutMs])
      if (!Number.isSafeInteger(value) || value < 1) throw failure();
    this.maximum = bounds.maxResultBytes + 2048;
    this.bufferedMaximum = this.maximum * bounds.maxQueuedEvents;
    if (!Number.isSafeInteger(this.bufferedMaximum)) throw failure();
    const native = socket.send.bind(socket);
    socket.once('close', () => {
      this.closed = true;
      for (const finish of [...this.writes]) finish(failure('EK_GQL_SUBSCRIPTION'));
    });
    socket.send = ((data: unknown, optionsOrCallback?: unknown, finalCallback?: unknown) => {
      const callback = typeof optionsOrCallback === 'function' ? optionsOrCallback : finalCallback;
      const notify = (error?: Error) => {
        try {
          if (typeof callback === 'function') callback(error);
        } catch {
          // Native callback failure must not repeat a write or notify another callback twice.
        }
      };
      let message: Message, encoded: string;
      try {
        if (
          this.closed ||
          typeof data !== 'string' ||
          Buffer.byteLength(data) > this.maximum ||
          (optionsOrCallback !== undefined && typeof optionsOrCallback !== 'function') ||
          this.writes.size >= bounds.maxQueuedEvents ||
          socket.bufferedAmount > this.bufferedMaximum
        )
          throw failure('EK_GQL_BACKPRESSURE');
        message = parseMessage(data);
        switch (message.type) {
          case MessageType.ConnectionAck:
          case MessageType.Ping:
          case MessageType.Pong:
          case MessageType.Complete:
            break;
          case MessageType.Next:
            if (Buffer.byteLength(JSON.stringify(message.payload)) > bounds.maxResultBytes)
              throw failure('EK_GQL_RESPONSE_LIMIT');
            break;
          case MessageType.Error:
            message = {
              ...message,
              payload: message.payload.map((error) =>
                subscriptionError(error, bounds.maxResultBytes),
              ),
            };
            break;
          default:
            throw failure('EK_GQL_SUBSCRIPTION');
        }
        if (
          (message.type === MessageType.Next || message.type === MessageType.Error) &&
          Buffer.byteLength(JSON.stringify(message.payload)) > bounds.maxResultBytes
        )
          throw failure('EK_GQL_RESPONSE_LIMIT');
        encoded = JSON.stringify(message);
        if (Buffer.byteLength(encoded) > this.maximum) throw failure('EK_GQL_RESPONSE_LIMIT');
        if (socket.bufferedAmount + Buffer.byteLength(encoded) > this.bufferedMaximum)
          throw failure('EK_GQL_BACKPRESSURE');
      } catch {
        this.closed = true;
        socket.terminate();
        notify(failure('EK_GQL_BACKPRESSURE'));
        return;
      }
      let settled = false;
      const finish = (error?: Error) => {
        if (settled) return;
        if (this.closed && !error) error = failure('EK_GQL_SUBSCRIPTION');
        settled = true;
        clearTimeout(timer);
        this.writes.delete(finish);
        if (error) {
          this.closed = true;
          socket.terminate();
          notify(failure('EK_GQL_SUBSCRIPTION'));
          return;
        }
        try {
          this.sent(message);
        } catch {
          this.closed = true;
          socket.terminate();
          notify(failure('EK_GQL_SUBSCRIPTION'));
          return;
        }
        notify();
      };
      const timer = setTimeout(() => finish(failure('EK_GQL_TIMEOUT')), bounds.timeoutMs);
      timer.unref();
      this.writes.add(finish);
      try {
        native(encoded, finish);
      } catch {
        finish(failure('EK_GQL_SUBSCRIPTION'));
      }
    }) as WebSocket['send'];
  }

  stats() {
    return Object.freeze({ pendingWrites: this.writes.size, closed: this.closed });
  }
}
