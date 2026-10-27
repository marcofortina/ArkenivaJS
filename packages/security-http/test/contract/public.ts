// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type {
  SecurityHttpService,
  HttpSecurityPolicy,
  SecurityHttpPluginSettings,
} from '../../dist/index.js';
import { securityHttpPlugin, SECURITY_HTTP_CAPABILITY } from '../../dist/index.js';
import type { Plugin } from '@arkenivajs/core';

declare const service: SecurityHttpService;
declare const settings: SecurityHttpPluginSettings;
const plugin: Plugin = securityHttpPlugin(settings);
const token: Promise<string> = service.csrfToken({ sessionId: 'server-verified' });
const verification: Promise<void> = service.verifyCsrf(
  { sessionId: 'server-verified', origin: 'https://app.example.invalid' },
  'opaque',
);
const policy: HttpSecurityPolicy = service.getEffectivePolicy();
// @ts-expect-error Origin is required for CSRF verification.
service.verifyCsrf({ sessionId: 'server-verified' }, 'opaque');
// @ts-expect-error Tokens are opaque strings, not constructed identity objects.
service.verifyCsrf({ sessionId: 'server-verified', origin: 'https://app.example.invalid' }, {});
void [plugin, token, verification, policy, SECURITY_HTTP_CAPABILITY];
