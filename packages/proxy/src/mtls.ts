// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { TLSSocket } from 'node:tls';
import { isIP } from 'node:net';
import { buildConnector } from 'undici';
import { within } from '@arkenivajs/core/support';
import type { MtlsService } from '@arkenivajs/security-mtls';
import type { ProxyRouteConfig } from './contracts.js';
import { guardedLookup } from './network.js';
import { failure, hostname } from './policy.js';
import { translated } from './runtime.js';

/** No HTTP bytes leave the connector until the actual peer passes asynchronous chain/revocation policy. */
export function mtlsConnector(
  route: ProxyRouteConfig,
  mtls: MtlsService,
): buildConnector.connector {
  const profile = route.upstreamTlsProfile!;
  const servername = hostname(new URL(route.upstreamOrigin).hostname);
  return (parameters, callback) => {
    let socket: TLSSocket | undefined,
      completed = false;
    const controller = new AbortController();
    const finish = (error: Error | null, connected?: TLSSocket) => {
      if (completed) {
        if (connected) connected.destroy();
        return;
      }
      completed = true;
      controller.abort();
      if (error) {
        socket?.destroy();
        callback(error, null);
      } else if (connected) callback(null, connected);
    };
    const failed = () => finish(failure('EK_PROXY_UPSTREAM'));
    void within(
      async () => {
        if (parameters.hostname !== servername) throw failure('EK_PROXY_POLICY');
        const material = await mtls.createClientOptions(profile, servername, {
          signal: controller.signal,
          timeoutMs: route.timeoutMs,
        });
        if (controller.signal.aborted) throw failure('EK_PROXY_TIMEOUT');
        const native = mtls.toNodeClientOptions(material);
        const options = {
          ...native,
          allowH2: false,
          lookup: guardedLookup(route),
          timeout: route.timeoutMs,
        };
        if (isIP(servername)) delete options.servername;
        const connect = buildConnector(options);
        socket = await new Promise<TLSSocket>((resolve, reject) =>
          connect(parameters, (error, connected) => {
            if (error) {
              reject(error);
              return;
            }
            if (completed || !(connected instanceof TLSSocket) || !connected.authorized) {
              connected?.destroy();
              reject(failure('EK_PROXY_UPSTREAM'));
              return;
            }
            connected.once('error', failed);
            resolve(connected);
          }),
        );
        const peer = socket.getPeerCertificate();
        if (!peer.raw?.length) throw failure('EK_PROXY_UPSTREAM');
        await mtls.verifyPeer(
          peer.raw,
          {
            trustRootsRef: profile.trustRootsRef,
            allowedIdentities: profile.allowedIdentities,
            hostname: servername,
            revocation: profile.revocation,
          },
          { signal: controller.signal, timeoutMs: route.timeoutMs },
        );
        if (socket.destroyed || !socket.authorized) throw failure('EK_PROXY_UPSTREAM');
        return socket;
      },
      { timeoutMs: route.timeoutMs },
    ).then(
      (connected) => {
        connected.off('error', failed);
        finish(null, connected);
      },
      (error) => finish(translated(error)),
    );
  };
}
