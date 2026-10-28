// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ProxyService, ProxyRouteConfig, ProxyDestinationPolicy } from '../../dist/index.js';
function boundary(service: ProxyService, route: ProxyRouteConfig) {
  const stats: Readonly<{
    activeRequests: number;
    forwardedRequests: number;
    rejectedRequests: number;
    observedRequestBytes: number;
    observedResponseBytes: number;
  }> = service.stats();
  const health: Readonly<{ configuredRoutes: number; ready: boolean }> = service.health();
  // @ts-expect-error The capability cannot register or redirect runtime routes.
  service.registerRoute(route);
  // @ts-expect-error A boolean is not a reviewed destination policy.
  const unsafe: ProxyDestinationPolicy = { allowPrivate: true };
  return { stats, health, unsafe };
}
void boundary;
