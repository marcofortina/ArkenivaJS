// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { ChannelCredentials, ServerCredentials } from '@grpc/grpc-js';
import { TLSSocket, createSecureContext } from 'node:tls';
import type { SecureServerOptions } from 'node:http2';
import type { MtlsService, TlsProfile } from '@arkenivajs/security-mtls';
import type { OperationOptions } from '@arkenivajs/core';
import { failure } from './errors.js';

/** Native TLS completes asynchronous chain/revocation checks before gRPC can send metadata or data. */
class VerifiedChannelCredentials extends ChannelCredentials {
  constructor(
    private readonly native: ChannelCredentials,
    private readonly verify: (socket: TLSSocket) => Promise<void>,
  ) {
    super();
  }
  override _isSecure(): boolean {
    return true;
  }
  override _equals(other: ChannelCredentials): boolean {
    return this === other;
  }
  override compose(credentials: Parameters<ChannelCredentials['compose']>[0]): ChannelCredentials {
    return new VerifiedChannelCredentials(this.native.compose(credentials), this.verify);
  }
  override _createSecureConnector(
    ...parameters: Parameters<ChannelCredentials['_createSecureConnector']>
  ): ReturnType<ChannelCredentials['_createSecureConnector']> {
    const connector = this.native._createSecureConnector(...parameters),
      verify = this.verify;
    return {
      waitForReady: () => connector.waitForReady(),
      getCallCredentials: () => connector.getCallCredentials(),
      destroy: () => connector.destroy(),
      async connect(socket) {
        const result = await connector.connect(socket);
        try {
          if (!result.secure || !(result.socket instanceof TLSSocket) || !result.socket.authorized)
            throw failure();
          await verify(result.socket);
          if (result.socket.destroyed || result.socket.closed) throw failure();
          return result;
        } catch {
          result.socket.destroy();
          throw failure();
        }
      },
    };
  }
}
/** Preserve native HTTP/2 TLS ownership while retaining the configured minimum TLS version. */
class OwnedServerCredentials extends ServerCredentials {
  constructor(options: SecureServerOptions) {
    super(options, options);
  }
  override _equals(other: ServerCredentials): boolean {
    return this === other;
  }
}
export async function clientCredentials(
  mtls: MtlsService,
  profile: TlsProfile,
  hostname: string,
  options: OperationOptions,
): Promise<ChannelCredentials> {
  const material = await mtls.createClientOptions(profile, hostname, options),
    native = mtls.toNodeClientOptions(material),
    context = createSecureContext(native);
  const credentials = ChannelCredentials.createFromSecureContext(context, {
    rejectUnauthorized: true,
  });
  return new VerifiedChannelCredentials(credentials, async (socket) => {
    const certificate = socket.getPeerCertificate();
    if (!certificate.raw?.length) throw failure();
    await mtls.verifyPeer(
      certificate.raw,
      {
        trustRootsRef: profile.trustRootsRef,
        allowedIdentities: profile.allowedIdentities,
        hostname,
        revocation: profile.revocation,
      },
      options,
    );
  });
}
export async function serverCredentials(
  mtls: MtlsService,
  profile: TlsProfile,
  options: OperationOptions,
  maxConcurrent = 4,
): Promise<ServerCredentials> {
  const material = await mtls.createServerOptions(profile, options),
    native = mtls.toNodeServerOptions(material);
  return new OwnedServerCredentials({
    ...native,
    requestCert: true,
    rejectUnauthorized: true,
    ALPNProtocols: ['h2'],
    handshakeTimeout: options.timeoutMs ?? 3000,
    maxHeaderListPairs: 128,
    maxOutstandingPings: 1,
    maxSessionMemory: 64,
    settings: { maxHeaderListSize: 16384, maxConcurrentStreams: maxConcurrent },
  });
}
