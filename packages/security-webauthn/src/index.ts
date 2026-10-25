// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** Browser-facing serialization shapes; credential responses remain untrusted input. */
export type WebAuthnOptionsJSON = Readonly<Record<string, unknown>>;

/** An expiring ceremony reference, never an authentication session or verification proof. */
export interface WebAuthnCeremony {
  readonly ceremonyId: string;
  readonly expiresAt: string;
  readonly optionsJSON: WebAuthnOptionsJSON;
}
