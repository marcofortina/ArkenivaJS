// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ItalianEidPluginSettings } from '../../dist/index.js';

declare const settings: ItalianEidPluginSettings;
const protectedState: ItalianEidPluginSettings = {
  ...settings,
  stateEncryptionKeyRefs: ['external-encryption-reference'],
  stateMacKeyRefs: ['external-mac-reference'],
};
const invalid: ItalianEidPluginSettings = {
  ...settings,
  // @ts-expect-error Protected state uses an explicit reference catalog, never a raw scalar.
  stateMacKeyRefs: 'invalid-reference-catalog',
};
void [protectedState, invalid];
