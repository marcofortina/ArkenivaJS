// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import type { FederationProfileV1 } from './contracts.js';
import { verifySamlMetadataSignature } from './saml-metadata-signature.js';
import { verifySamlRegistryDocument } from './saml-registry-document.js';

const input = workerData as {
  xml: string;
  profile: FederationProfileV1;
  role: 'idp' | 'sp';
  status?: string;
};
try {
  const result =
    input.status === undefined
      ? verifySamlMetadataSignature(input.xml, input.profile, input.role)
      : verifySamlRegistryDocument(input.xml, input.status, input.profile, input.role);
  parentPort!.postMessage({ ok: true, result });
} catch {
  parentPort!.postMessage({ ok: false });
} finally {
  parentPort!.close();
}
