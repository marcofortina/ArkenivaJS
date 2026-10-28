// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { realtimePlugin, REALTIME_CAPABILITY, SseCursorError } from '@arkenivajs/realtime';
import type {
  RealtimeService,
  RealtimeSession,
  RealtimePluginSettings,
  SseSource,
  SseSourceContext,
  RealtimeIdentityAuthority,
} from '@arkenivajs/realtime';
import type { Plugin } from '@arkenivajs/core';

const source: SseSource = {
  kind: 'durable',
  usage: 'test-only',
  async validateCursor(context: SseSourceContext) {
    if (context.lastEventId) throw new SseCursorError('invalid');
  },
  async *subscribe() {
    yield { id: 'event_1', type: 'update', data: 'text' };
  },
};
export function plugin(settings: RealtimePluginSettings): Plugin {
  return realtimePlugin(settings);
}
export async function use(service: RealtimeService, session: RealtimeSession) {
  const capability: symbol = REALTIME_CAPABILITY;
  await service.publish('channel', new Uint8Array(), session.authenticatedTenant, {
    timeoutMs: 1000,
    signal: session.signal,
  });
  await session.send({ channel: 'channel', payload: new Uint8Array(), id: 'event_1' });
  for await (const message of session.receive()) {
    const bytes: Uint8Array = message.payload;
    void bytes;
  }
  return { capability, source };
}
export function authority(value: RealtimeIdentityAuthority): RealtimeIdentityAuthority {
  return value;
}
// @ts-expect-error Anonymous realtime policies are intentionally unsupported.
const anonymous: import('@arkenivajs/realtime').RealtimePolicy['requireAuth'] = false;
// @ts-expect-error Wire strings do not replace the byte-preserving public message payload.
const payload: import('@arkenivajs/realtime').RealtimeMessage['payload'] = 'text';
void anonymous;
void payload;
