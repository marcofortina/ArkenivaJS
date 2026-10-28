// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '@arkenivajs/security-magiclink';
import type {
  MagicLinksPluginSettings,
  MagicLinkService,
  MagicLinkAuthority,
  IdentitySubject,
} from '@arkenivajs/security-magiclink';
import { apiKeyFixture } from './api-key-fixture.js';

/** Real signed authentication, authoritative account lookup and independent PostgreSQL state adapters. */
export async function magicLinkFixture(
  maxClaims = 8,
  ttlMs = 60000,
  trustedBaseUrl = 'https://identity.fixture.invalid/confirm',
) {
  const base = await apiKeyFixture(),
    accounts = new Map<string, IdentitySubject>(),
    applications: Awaited<ReturnType<typeof createApplication>>[] = [];
  const key = (issuer: string, subject: string, tenantId: string) =>
    JSON.stringify([issuer, subject, tenantId]);
  const authority: MagicLinkAuthority & { usage: 'test-only' } = {
    usage: 'test-only',
    async require(action, hint, context) {
      if (!base.state.authorityAvailable || !base.state.accountEnabled)
        throw new Error('The authoritative account directory is unavailable');
      if (action.startsWith('magiclink.consume.')) {
        if (!hint || context.magicLink?.tenantId === undefined)
          throw new Error('An independently resolved account binding is required');
        const account = accounts.get(key(hint.issuer, hint.subject, context.magicLink.tenantId));
        if (!account || !base.auth.isVerifiedTenant(account.tenant))
          throw new Error('The account membership is not current');
        const current = base.currentIdentity();
        if (current && base.auth.tenantFrom(current).tenantId !== account.tenant!.tenantId)
          throw new Error('The current authenticated tenant cannot redeem a foreign account link');
        return account;
      }
      const current = base.currentIdentity();
      if (!current) throw new Error('An independent authenticated session is required');
      base.auth.requireScope(current, 'magiclink:manage');
      const tenant = base.auth.tenantFrom(current),
        account = accounts.get(key(current.issuer, current.subject, tenant.tenantId));
      if (
        !account ||
        account.tenant !== tenant ||
        (hint &&
          (hint.issuer !== account.issuer ||
            hint.subject !== account.subject ||
            hint.tenant !== account.tenant))
      )
        throw new Error('The authenticated owner cannot manage the requested link');
      return account;
    },
  };
  const settings: MagicLinksPluginSettings = {
    stateStore: base.settings.store,
    hmac: base.settings.hmac,
    signingKeyRef: base.settings.hmacKeyRef,
    authority,
    trustedBaseUrl,
    ttlMs,
    maxClaimsPerHour: maxClaims,
  };
  async function instance(peer: boolean) {
    const app = await createApplication({
      service: { name: 'magiclink-postgres', version: '1.0.0', environment: 'test' },
      logging: { level: 'silent' },
      plugins: [
        loggingPlugin(),
        magicLinksPlugin({
          ...settings,
          stateStore: {
            ...settings.stateStore,
            store: peer ? base.backend.peer : settings.stateStore.store,
          },
        }),
      ],
    });
    applications.push(app);
    await app.start();
    return { app, magic: app.resolve<MagicLinkService>(MAGICLINK_CAPABILITY) };
  }
  try {
    const first = await instance(false),
      second = await instance(true);
    return {
      base,
      settings,
      first,
      second,
      async session(claims: Record<string, unknown> = {}) {
        const session = await base.session({ scope: 'magiclink:manage', ...claims }),
          subject = session.subject;
        accounts.set(key(subject.issuer, subject.subject, subject.tenant.tenantId), subject);
        return session;
      },
      async close() {
        try {
          await Promise.all(applications.map((app) => app.stop()));
        } finally {
          await base.close();
        }
      },
    };
  } catch (error) {
    await Promise.allSettled(applications.map((app) => app.stop()));
    await base.close();
    throw error;
  }
}
