// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Plugin, OperationOptions } from '@arkenivajs/core';
import { webhooksPlugin, WEBHOOKS_CAPABILITY } from '../../dist/index.js';
import type {
  WebhookService,
  WebhookContext,
  WebhookSignature,
  VerifiedWebhook,
  WebhookEvent,
  WebhookDelivery,
  WebhooksPluginSettings,
  WebhookAuthority,
  WebhookAuthorizationContext,
} from '../../dist/index.js';

/** Public contracts compile without importing private helpers or starting any resource. */
export async function publicContract(
  service: WebhookService,
  settings: WebhooksPluginSettings,
  context: WebhookContext,
  signature: WebhookSignature,
  event: WebhookEvent,
  options: OperationOptions,
) {
  const plugin: Plugin = webhooksPlugin(settings),
    capability: symbol = WEBHOOKS_CAPABILITY;
  const signed: WebhookSignature = await service.sign(
    new Uint8Array(),
    'reference',
    context,
    options,
  );
  const verified: VerifiedWebhook = await service.verify(
    new Uint8Array(),
    signature,
    context,
    options,
  );
  const delivered: WebhookDelivery = await service.send('receiver', event, options);
  const parsed: WebhookEvent = service.parseEvent(new Uint8Array());
  const authority: WebhookAuthority = settings.authority;
  const scope: WebhookAuthorizationContext = { destinationId: 'receiver', eventId: 'one' };
  // @ts-expect-error Provider objects, replay persistence and finite policy are required.
  webhooksPlugin({ destinations: [] });
  // @ts-expect-error Raw bytes cannot be replaced with a reserialized object.
  await service.verify({ payload: 'x' }, signature, context);
  // @ts-expect-error The scoped policy cannot substitute an arbitrary identity or tenant claim.
  await service.sign(new Uint8Array(), 'reference', { ...context, tenantId: 'forged' });
  void [plugin, capability, signed, verified, delivered, parsed, authority, scope];
}
