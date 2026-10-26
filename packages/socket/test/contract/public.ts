// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { socketPlugin } from '../../dist/index.js';
import type { SocketService, SocketPeer } from '../../dist/index.js';

/** Positive and negative fixtures compile against the actual public package surface. */
export function contracts(service: SocketService, peer: SocketPeer) {
  socketPlugin({
    listeners: [
      {
        kind: 'udp',
        options: { name: 'datagrams', family: 'udp4', port: 9002 },
        handler: async (value, server) => {
          await server.reply(value, value.bytes);
        },
      },
    ],
  });
  const tcp = service.createTcpServer({ name: 'stream', port: 9001 }, async (value) => {
    for await (const bytes of value.chunks()) await value.send(bytes);
  });
  // @ts-expect-error Raw streams accept bytes rather than implicit text encoding.
  void peer.send('payload');
  // @ts-expect-error TCP listeners cannot silently accept UDP-only options.
  service.createTcpServer({ name: 'wrong', port: 9001, family: 'udp4' }, () => undefined);
  // @ts-expect-error A UDP listener requires an explicit address family.
  service.createUdpServer({ name: 'wrong', port: 9001 }, () => undefined);
  // @ts-expect-error TLS listeners require their external file policy.
  service.createTlsServer({ name: 'wrong', port: 9443 }, () => undefined);
  return tcp;
}
