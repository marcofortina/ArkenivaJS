// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { cryptoPlugin } from '@arkenivajs/security-crypto';
import { oauthClientPlugin, OAUTH_CLIENT_CAPABILITY } from '@arkenivajs/security-oauth-client';
import { runPureWorker } from './pure-worker.mjs';
import { oauthPorts, oauthSettings, nativeOAuth, verifyOAuth } from './oauth-workload.mjs';

runPureWorker({
  name: 'oauth',
  asynchronous: true,
  native: nativeOAuth,
  framework(fixture) {
    const ports = oauthPorts(fixture);
    return {
      plugin: oauthClientPlugin(oauthSettings(fixture, ports)),
      key: OAUTH_CLIENT_CAPABILITY,
      plugins: [
        cryptoPlugin({
          secrets: ports.secretProvider,
          encryptionKeyRefs: ['enc'],
          signingKeyRefs: ['mac'],
          policy: {
            maxConcurrent: 4,
            timeoutMs: 10000,
            maxInputBytes: 65536,
            maxOutputBytes: 65536,
          },
        }),
      ],
    };
  },
  verify: verifyOAuth,
  workload() {
    throw new Error(
      'OAuth performance sampling requires an explicit paired authorization and durable-state workload',
    );
  },
});
