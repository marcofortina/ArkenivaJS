// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Http2SecureServer } from 'node:http2';
import type { FastifyInstance } from 'fastify';
import { createApi, type ApiOptions, type ManagedApiServer } from '@arkenivajs/api';

function contract(options: ApiOptions): void {
  const secure: ManagedApiServer<Http2SecureServer> = createApi({ ...options, http2: true });
  const http1: ManagedApiServer = createApi({ ...options, http2: false });
  const native: FastifyInstance<Http2SecureServer> = secure.native();
  // @ts-expect-error HTTP2 raw servers cannot be silently typed as HTTP1 servers.
  const incorrect: ManagedApiServer = secure;
  void [native, http1, incorrect];
}
void contract;
