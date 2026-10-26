// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ConnectionOptions, TlsOptions } from 'node:tls';
import type {
  MtlsService,
  TlsClientOptions,
  TlsProfile,
  TlsServerOptions,
} from '@arkenivajs/security-mtls';

/** Compile the actual exported adapter converters against the pinned native TLS definitions. */
export async function nativeTypes(mtls: MtlsService, profile: TlsProfile) {
  const client = await mtls.createClientOptions(profile, 'localhost');
  const server = await mtls.createServerOptions(profile);
  const nativeClient: ConnectionOptions = mtls.toNodeClientOptions(client);
  const nativeServer: TlsOptions = mtls.toNodeServerOptions(server);
  // @ts-expect-error Server material is not client material and has no verified servername.
  mtls.toNodeClientOptions(server);
  // @ts-expect-error Native options cannot accept the unconverted byte-material shape.
  const unconverted: ConnectionOptions = client;
  // @ts-expect-error Insecure TLS flags are outside the public client contract.
  const insecure: TlsClientOptions = { ...client, rejectUnauthorized: false };
  // @ts-expect-error A mutually authenticated server must request a client certificate.
  const anonymous: TlsServerOptions = { ...server, requestCert: false };
  return { nativeClient, nativeServer, unconverted, insecure, anonymous };
}
