// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import type { FederationProfileV1 } from './contracts.js';
import { verifySamlMetadataSignature } from './saml-metadata-signature.js';

const input = workerData as { xml: string; profile: FederationProfileV1; role: 'idp' | 'sp' };
try {
  const result = verifySamlMetadataSignature(input.xml, input.profile, input.role);
  parentPort!.postMessage({ ok: true, result });
} catch {
  parentPort!.postMessage({ ok: false });
} finally {
  parentPort!.close();
}
