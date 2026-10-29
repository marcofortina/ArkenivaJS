// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { ciePlugin, CIE_CAPABILITY } from '../../dist/index.js';
import { runPublicOidc } from '../../../identity-spid/dist-test/fixtures/public-oidc-worker.js';

process.once(
  'message',
  (input: { certificate: string; privateKey: string; telemetryMode?: 'standard' | 'detailed' }) => {
    void runPublicOidc(input, {
      system: 'cie',
      capability: CIE_CAPABILITY,
      factory: ciePlugin,
    }).then(
      () => {
        process.send?.({ ok: true, mode: 'public' });
        process.disconnect();
      },
      (error: unknown) => {
        process.send?.({
          ok: false,
          message: error instanceof Error ? error.message : 'CIE fixture failed',
        });
        process.disconnect();
      },
    );
  },
);
