// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { fixtureSettings } from '../../security-apikey/dist-test/unit/fixture.js';
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '../dist/index.js';
import type { MagicLinksPluginSettings, MagicLinkService } from '../dist/index.js';

/** Unit state only; real shared PostgreSQL and signed authentication remain integration gates. */
export function fixture() {
  const source = fixtureSettings();
  const settings: MagicLinksPluginSettings = {
    stateStore: source.settings.store,
    hmac: source.settings.hmac,
    signingKeyRef: source.settings.hmacKeyRef,
    trustedBaseUrl: 'https://identity.fixture.invalid/confirm',
    ttlMs: 60000,
    maxClaimsPerHour: 4,
    authority: {
      async require(action, hint) {
        if (
          !source.state.enabled ||
          (!action.startsWith('magiclink.consume.') && !source.state.authenticated) ||
          (hint &&
            (hint.issuer !== source.owner.issuer ||
              hint.subject !== source.owner.subject ||
              hint.tenant !== undefined))
        )
          throw new Error('The independent unit authorization policy rejected the operation');
        return source.owner;
      },
    },
  };
  return { ...source, settings };
}
export async function application(
  settings: MagicLinksPluginSettings,
  environment: 'test' | 'production' = 'test',
) {
  const app = await createApplication({
    service: { name: 'magiclink-fixture', version: '1.0.0', environment },
    logging: { level: 'silent' },
    plugins: [loggingPlugin(), magicLinksPlugin(settings)],
  });
  try {
    await app.start();
  } catch (error) {
    await app.stop();
    throw error;
  }
  return { app, magic: app.resolve<MagicLinkService>(MAGICLINK_CAPABILITY) };
}
