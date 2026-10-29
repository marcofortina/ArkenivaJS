// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import type { ServerTlsFiles } from '@arkenivajs/core';

/** These inputs are supplied only inside the owned disposable integration VM. */
export function productionAuthority() {
  assert.equal(process.env.ARKENIVA_GRAPHQL_PRODUCTION_FIXTURE, '1');
  const host = process.env.ARKENIVA_GRAPHQL_AUTHORITY_HOST,
    certificateFile = process.env.ARKENIVA_GRAPHQL_AUTHORITY_CERT,
    privateKeyFile = process.env.ARKENIVA_GRAPHQL_AUTHORITY_KEY;
  assert.ok(host && certificateFile && privateKeyFile);
  return { host, tls: { certificateFile, privateKeyFile } satisfies ServerTlsFiles };
}
