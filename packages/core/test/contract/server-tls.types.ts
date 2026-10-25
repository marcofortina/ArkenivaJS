// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ServerTlsFiles } from '../../dist/index.js';

function contract(files: ServerTlsFiles): void {
  const configured: ServerTlsFiles = {
    ...files,
    minVersion: 'TLSv1.3',
    clientCertificate: 'required',
    caFile: '/run/secrets/ca.pem',
  };
  // @ts-expect-error Legacy insecure TLS versions are outside the server policy.
  const insecure: ServerTlsFiles = { ...files, minVersion: 'TLSv1.1' };
  // @ts-expect-error File policy cannot contain raw key material.
  const plaintext: ServerTlsFiles = { ...files, key: 'private-material' };
  // @ts-expect-error Certificate references are immutable startup configuration.
  files.certificateFile = '/changed';
  void [configured, insecure, plaintext];
}
void contract;
