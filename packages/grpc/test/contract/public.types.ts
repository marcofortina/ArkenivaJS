// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { GrpcClient, GrpcService, GrpcCallOptions } from '../../dist/index.js';
import type { TrustedSecurityAuthority } from '../../dist/index.js';
import type { TrustedSecurityAuthority as SharedAuthority } from '@arkenivajs/security-apikey';
/** Security authority implementations remain interchangeable with the shared identity contract. */
function sharedAuthority(local: TrustedSecurityAuthority, shared: SharedAuthority) {
  const existing: SharedAuthority = local,
    grpc: TrustedSecurityAuthority = shared;
  return { existing, grpc };
}
void sharedAuthority;
function boundary(service: GrpcService, client: GrpcClient) {
  const reply: Promise<{ quantity: number }> = client.unary('ReadStock', { sku: '0007' });
  const stream: AsyncIterable<{ quantity: number }> = client.serverStream('WatchStock', {
    sku: '0007',
  });
  const native: unknown = client.native(),
    server: unknown = service.nativeServer();
  // @ts-expect-error Call options cannot replace the configured destination.
  const unsafe: GrpcCallOptions = { endpoint: 'other.invalid:443' };
  return { reply, stream, native, server, unsafe };
}
void boundary;
