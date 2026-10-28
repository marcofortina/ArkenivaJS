// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { SoapService, SoapClient, SoapResult, SoapPluginSettings } from '../../dist/index.js';
import { soapPlugin, SOAP_CAPABILITY } from '../../dist/index.js';
import type { Application, Plugin } from '@arkenivajs/core';
function boundary(soap: SoapService, client: SoapClient) {
  const pending: Promise<SoapClient> = soap.createClient('partner.v1', { timeoutMs: 1000 });
  const result: Promise<SoapResult<{ id: string }>> = client.call('ReadItem', { id: '001' });
  const actual: unknown = client.native();
  // @ts-expect-error Requests cannot change the deployment endpoint through call options.
  client.call('ReadItem', {}, { endpoint: 'https://untrusted.invalid' });
  return { pending, result, actual };
}
declare const settings: SoapPluginSettings;
declare const app: Application;
const plugin: Plugin = soapPlugin(settings),
  service = app.resolve<SoapService>(SOAP_CAPABILITY);
// @ts-expect-error A real secret provider is mandatory even for profiles without credentials.
soapPlugin({ services: settings.services, policy: settings.policy, secretProvider: {} });
const protocol: SoapPluginSettings = {
  ...settings,
  // @ts-expect-error SOAP protocol versions are explicit and finite.
  services: [{ ...settings.services[0]!, protocol: '2.0' }],
};
void [boundary, protocol, plugin, service];
