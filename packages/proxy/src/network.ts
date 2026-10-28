// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { lookup } from 'node:dns';
import type { LookupFunction } from 'node:net';
import type { ProxyRouteConfig } from './contracts.js';
import { allowedAddress, hostname, failure } from './policy.js';

/** Native connect-time resolution checks every returned address before the transport selects one. */
export function guardedLookup(
  route: ProxyRouteConfig,
  resolve: typeof lookup = lookup,
): LookupFunction {
  const expected = hostname(new URL(route.upstreamOrigin).hostname);
  return (host, options, callback) => {
    if (host !== expected) {
      callback(failure('EK_PROXY_POLICY'), '', 0);
      return;
    }
    let finished = false;
    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        callback(failure('EK_PROXY_TIMEOUT'), '', 0);
      }
    }, route.timeoutMs);
    resolve(host, { all: true, verbatim: true }, (error, addresses) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (
        error ||
        !addresses.length ||
        addresses.length > 64 ||
        addresses.some((value) => !allowedAddress(value.address, route.destinationPolicy))
      ) {
        callback(failure(error ? 'EK_PROXY_UPSTREAM' : 'EK_PROXY_POLICY'), '', 0);
        return;
      }
      const selected = addresses.filter(
        (value) => !options.family || value.family === options.family,
      );
      if (!selected.length) {
        callback(failure('EK_PROXY_UPSTREAM'), '', 0);
        return;
      }
      if (options.all) callback(null, selected);
      else callback(null, selected[0]!.address, selected[0]!.family);
    });
  };
}
