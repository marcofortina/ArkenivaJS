// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Plugin } from '@arkenivajs/core';
import { spidPlugin } from '../../dist/index.js';
import type { ItalianEidPluginSettings, SpidService, FederatedLogin } from '../../dist/index.js';

declare const settings: ItalianEidPluginSettings;
declare const service: SpidService;
const plugin: Plugin = spidPlugin(settings);
const selected: SpidService = service.forProfile('approved-profile');
const login: Promise<FederatedLogin> = selected.beginAuthentication(
  { returnPath: '/private', issuer: 'https://approved-provider.example.test' },
  'spid-l2',
  { timeoutMs: 1000 },
);
// @ts-expect-error Profile selection is an explicit configured string identifier.
service.forProfile({ profileId: 'untrusted' });
// @ts-expect-error A provider selector is an issuer string, never caller-supplied metadata.
service.beginAuthentication({ returnPath: '/private', issuer: { trusted: true } }, 'spid-l2');
void [plugin, selected, login];
