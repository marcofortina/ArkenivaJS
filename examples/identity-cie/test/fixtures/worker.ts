// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPublicOidc } from './public-oidc-worker.js';
process.once(
  'message',
  (input: { certificate: string; privateKey: string; telemetryMode?: 'standard' | 'detailed' }) => {
    void runPublicOidc(input).then(
      () => {
        process.send?.({ ok: true, mode: 'public' });
        process.disconnect();
      },
      (error: unknown) => {
        process.send?.({
          ok: false,
          message: error instanceof Error ? error.message : 'The public CIE fixture failed',
        });
        process.disconnect();
      },
    );
  },
);
