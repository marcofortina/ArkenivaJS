// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { FederationAssurance, ItalianIdentitySystem } from './contracts.js';
import { failure } from './validation.js';

const levels: Readonly<Record<ItalianIdentitySystem, readonly FederationAssurance[]>> =
  Object.freeze({
    spid: Object.freeze(['spid-l1', 'spid-l2', 'spid-l3'] as const),
    cie: Object.freeze(['cie-l1', 'cie-l2', 'cie-l3'] as const),
  });
/** Both Italian OIDC profiles use these wire references; application assurance retains its own system. */
export const acrValues = Object.freeze([
  'https://www.spid.gov.it/SpidL1',
  'https://www.spid.gov.it/SpidL2',
  'https://www.spid.gov.it/SpidL3',
]);
export function assuranceLevels(system: ItalianIdentitySystem): readonly FederationAssurance[] {
  if (system !== 'spid' && system !== 'cie') throw failure('EK_EID_ASSURANCE');
  return levels[system];
}
export function assuranceContext(
  system: ItalianIdentitySystem,
  assurance: FederationAssurance,
): string {
  const index = assuranceLevels(system).indexOf(assurance);
  if (index < 0) throw failure('EK_EID_ASSURANCE');
  return acrValues[index]!;
}
