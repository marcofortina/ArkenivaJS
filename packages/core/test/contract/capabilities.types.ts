// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { Application } from '@arkenivajs/core';

function publicResolution(app: Application, key: symbol) {
  const value: { readonly ready: boolean } = app.resolve<{ readonly ready: boolean }>(key);
  const optional: typeof value | undefined = app.tryResolve<typeof value>(key);
  // @ts-expect-error Capability identifiers remain symbols, never fragile string service names.
  app.resolve('service');
  // @ts-expect-error Resolution has no request-controlled lifecycle or configuration override.
  app.resolve(key, { initializing: true });
  const unknown = app.resolve(key);
  // @ts-expect-error Omitting a service type never creates an implicit any escape hatch.
  void unknown.ready;
  return { value, optional };
}
void publicResolution;
