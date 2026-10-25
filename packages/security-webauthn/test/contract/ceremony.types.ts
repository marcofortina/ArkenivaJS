// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { WebAuthnCeremony, WebAuthnOptionsJSON } from '../../dist/index.js';

function contracts(ceremony: WebAuthnCeremony): void {
  const options: WebAuthnOptionsJSON = ceremony.optionsJSON;
  // @ts-expect-error A browser ceremony is immutable and cannot establish a session.
  ceremony.ceremonyId = 'replacement';
  // @ts-expect-error A challenge response is untrusted, not an issued MFA proof.
  const evidence: { verified: true } = ceremony;
  void [options, evidence];
}
void contracts;
