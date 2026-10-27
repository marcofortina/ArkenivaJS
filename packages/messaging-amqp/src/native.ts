// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Duplex } from 'node:stream';
import type { Channel, ChannelModel, MessageProperties, RecoveringChannelModel } from 'amqplib';
import type { AmqpHeaders } from './contracts.js';
import { incoming } from './headers.js';

/** Narrow ports into the pinned native lifecycle and message assembly machinery. */
export type Model = ChannelModel & {
  readonly connection: ChannelModel['connection'] & { readonly stream: Duplex };
};
export type Recovery = RecoveringChannelModel & {
  readonly _core: { _openModel(): Promise<Model> };
};
interface Frame {
  readonly size?: unknown;
  readonly fields?: MessageProperties;
}
type NativeChannel = Channel & { acceptMessageFrame(frame: Frame): unknown };

/** Inspect decoded native headers before the approved assembler can retain a complete body. */
export function guardMessages(channel: Channel, maximum: number, reject: () => void) {
  const native = channel as NativeChannel,
    accept = native.acceptMessageFrame.bind(native),
    prepared = new WeakMap<object, AmqpHeaders>();
  let stopped = false;
  channel.once('close', () => {
    stopped = true;
  });
  Object.defineProperty(native, 'acceptMessageFrame', {
    value: (frame: Frame) => {
      if (stopped) return;
      try {
        if (Object.hasOwn(frame, 'size')) {
          if (
            typeof frame.size !== 'number' ||
            !Number.isSafeInteger(frame.size) ||
            frame.size < 0 ||
            frame.size > maximum ||
            !frame.fields
          )
            throw new Error('Native message bounds exceeded');
          prepared.set(frame.fields, incoming(frame.fields.headers));
        }
      } catch {
        stopped = true;
        reject();
        return;
      }
      return accept(frame);
    },
    configurable: false,
    writable: false,
  });
  return {
    headers(properties: MessageProperties): AmqpHeaders {
      return prepared.get(properties) ?? incoming(properties.headers);
    },
  };
}
