// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { passwordPlugin } from '../../dist/index.js';
import type {
  PasswordPluginSettings,
  PasswordService,
  PasswordPolicy,
  PasswordHash,
  IdentitySubject,
  SecurityStateStore,
} from '../../dist/index.js';

/** Verify public signatures and deliberately rejected calls without invoking native work. */
export function publicContract(
  settings: PasswordPluginSettings,
  service: PasswordService,
  policy: PasswordPolicy,
  stored: PasswordHash,
  subject: IdentitySubject,
  partial: SecurityStateStore,
) {
  passwordPlugin(settings);
  // @ts-expect-error Reset persistence cannot be split into uncoordinated callbacks.
  passwordPlugin({ ...settings, resetCommitter: undefined });
  // @ts-expect-error Partial state lacks native batch and epoch guarantees.
  passwordPlugin({ ...settings, resetStore: { ...settings.resetStore, store: partial } });
  // @ts-expect-error Input policy remains immutable.
  policy.minLength = 1;
  // @ts-expect-error A production caller cannot replace the clock.
  service.consumeReset('invalid', 'invalid', { now: 0 });
  // @ts-expect-error Stored hashes use the prescribed Argon2id scheme.
  service.verify('invalid', { scheme: 'sha1', phc: 'invalid' });
  return [
    service.hash('invalid', policy),
    service.verify('invalid', stored),
    service.needsRehash(stored),
    service.createReset(subject, subject),
    service.consumeReset('invalid', 'invalid'),
  ];
}
