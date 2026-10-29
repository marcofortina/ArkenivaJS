// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication } from '@arkenivajs/core';
import type { ApplicationOptions } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { securityPlugin } from '@arkenivajs/security';
import { loggingPlugin } from '@arkenivajs/logging';
import {
  tenantRoutingPlugin,
  tenantRegistryFileProvider,
  TENANT_ROUTING_CAPABILITY,
} from '@arkenivajs/tenant-routing';
import type {
  ApprovedUpstream,
  TenantRoutingEventExporter,
  TenantRoutingService,
  TenantUpstreamCredentialProvider,
} from '@arkenivajs/tenant-routing';
import type { Writable } from 'node:stream';

/** Trusted deployment inputs; request data never chooses a registry or upstream. */
export interface TenantRoutingExampleOptions {
  readonly service: ApplicationOptions['service'];
  readonly http: NonNullable<ApplicationOptions['http']>;
  readonly issuer: string;
  readonly audience: string;
  readonly registryFile: string;
  readonly approvedUpstreams: readonly ApprovedUpstream[];
  readonly allowInsecureLoopback?: boolean;
  readonly eventExporter?: TenantRoutingEventExporter;
  readonly credentialProvider?: TenantUpstreamCredentialProvider;
  readonly destination?: Writable;
}

/** This fixed business/transform catalog is unchanged across registry rollouts. */
export async function createTenantRoutingExample(options: TenantRoutingExampleOptions) {
  const app = await createApplication({
    service: options.service,
    http: options.http,
    security: { issuer: options.issuer, audience: options.audience, algorithms: ['ES256'] },
    plugins: [
      loggingPlugin(options.destination ? { destination: options.destination } : {}),
      securityPlugin({ allowInsecureLoopback: options.allowInsecureLoopback ?? false }),
      apiPlugin({ dependencies: ['security'] }),
      tenantRoutingPlugin({
        activation: 'startup',
        registry: tenantRegistryFileProvider({
          absolutePath: options.registryFile,
          maxBytes: 8388608,
          environment: options.service.environment,
        }),
        approvedUpstreams: options.approvedUpstreams,
        ...(options.eventExporter ? { eventExporter: options.eventExporter } : {}),
        ...(options.credentialProvider ? { credentialProvider: options.credentialProvider } : {}),
        handlers: {
          'quotes.standard': (context) => ({
            quoteId: 'local-standard',
            total: (context.body as { amount: number }).amount,
          }),
          'orders.status': (context) => ({ orderId: context.params.orderId, status: 'accepted' }),
        },
        requestTransformers: {
          'quotes.partner.request': (payload) => ({
            subtotal: (payload as { amount: number }).amount,
          }),
        },
        responseTransformers: {
          'quotes.partner.response': (payload) => {
            const result = payload as { reference: string; netAmount: number };
            return { quoteId: result.reference, total: result.netAmount };
          },
        },
        authorize: ({ tenant, policy }) =>
          policy.requiredScopes.every((scope) => tenant.identity.scopes.includes(scope)),
      }),
    ],
  });
  app.api.get('/status', {
    auth: { required: false },
    schema: {
      response: {
        type: 'object',
        properties: { ready: { type: 'boolean' } },
        required: ['ready'],
        additionalProperties: false,
      },
    },
    handler: () => ({ ready: app.state === 'READY' }),
  });
  return { app, service: () => app.resolve<TenantRoutingService>(TENANT_ROUTING_CAPABILITY) };
}
