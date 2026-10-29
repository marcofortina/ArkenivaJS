// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createSamlService, samlPlugin } from '../../dist/index.js';
import type {
  SamlSettings,
  SamlLoginRequest,
  SamlLogoutRequest,
  SamlVerifiedIdentity,
} from '../../dist/index.js';

export function contract(settings: SamlSettings, identity: SamlVerifiedIdentity): void {
  const service = createSamlService(settings);
  samlPlugin(settings);
  void service.beginLogin({ returnPath: '/app' }, { timeoutMs: 4000 });
  void service.consumeResponse({ inResponseTo: '_request', relayState: '_request' }, 'base64', {
    signal: new AbortController().signal,
  });
  void service.beginLogout(identity);
  void service.consumeLogoutResponse('base64');
  void service.createMetadata();
  createSamlService({
    ...settings,
    requestedAuthnContext: {
      classReferences: ['https://www.spid.gov.it/SpidL2'],
      comparison: 'minimum',
      acceptedClassReferences: ['https://www.spid.gov.it/SpidL2', 'https://www.spid.gov.it/SpidL3'],
    },
  });
  createSamlService({
    ...settings,
    // @ts-expect-error A requested context requires an explicit accepted class catalog.
    requestedAuthnContext: { classReferences: ['urn:example:context'], comparison: 'exact' },
  });
  // @ts-expect-error Unknown configuration fields are rejected by the public contract.
  createSamlService({ ...settings, trustEveryCertificate: true });
  // @ts-expect-error Login requires an explicit local return path.
  void service.beginLogin({ redirectUrl: 'https://foreign.invalid' });
}
export function transfer(request: SamlLoginRequest | SamlLogoutRequest): string {
  if (request.binding === 'post') {
    // @ts-expect-error A POST binding has no redirect URL.
    void request.redirectUrl;
    return request.actionUrl + request.fields.SAMLRequest;
  }
  // @ts-expect-error A Redirect binding has no POST form fields.
  void request.fields;
  return request.redirectUrl;
}
