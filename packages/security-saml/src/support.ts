// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { types } from 'node:util';
import { captureAbortSignal } from '@arkenivajs/core/support';
import type { SamlService, SamlSettings } from './contracts.js';
import { capture } from './settings.js';
import { managed } from './service.js';
import { failure } from './validation.js';

/** Trusted framework composition over the same bounded native SAML runtime. */
export interface ManagedSamlAdapter {
  readonly service: SamlService;
  bootstrap(): Promise<void>;
  /** Bounded shutdown; a rejected deadline does not imply provider settlement. */
  close(): Promise<void>;
  /** Irreversibly stop admission and await actual provider/worker settlement without a public deadline. */
  drain(): Promise<void>;
}

/** Deployment-owned lifecycle inputs only; never populate these from protocol requests. */
export function createManagedSamlAdapter(
  settings: SamlSettings,
  owner: AbortSignal,
  ready: () => boolean,
): ManagedSamlAdapter {
  if (typeof ready !== 'function' || types.isProxy(ready) || types.isAsyncFunction(ready))
    throw failure();
  let signal: AbortSignal;
  try {
    signal = captureAbortSignal(owner);
  } catch {
    throw failure();
  }
  const current = () => {
    try {
      const decision: unknown = Reflect.apply(ready, undefined, []);
      if (types.isPromise(decision))
        void Promise.prototype.then.call(
          decision,
          () => undefined,
          () => undefined,
        );
      return decision === true;
    } catch {
      throw failure('EK_LIFECYCLE_STATE');
    }
  };
  return Object.freeze(managed(capture(settings), signal, current));
}
