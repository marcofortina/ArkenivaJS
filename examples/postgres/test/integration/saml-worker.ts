// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createApplication, KitError } from '@arkenivajs/core';
import { postgresPlugin } from '@arkenivajs/database-postgres';
import { createSamlService } from '@arkenivajs/security-saml';
import type { SamlService, SamlSettings } from '@arkenivajs/security-saml';
import { createPostgresSecurityStateStore } from '../../dist/security-state-store.js';

interface Start {
  type: 'start';
  schema: string;
  settings: Omit<SamlSettings, 'secretProvider' | 'replayStore' | 'authority'>;
  key: string;
  certificate: string;
}
let database: Awaited<ReturnType<typeof createApplication>> | undefined,
  service: SamlService | undefined,
  started = false,
  consuming = false;
let phase = 'idle';
async function close() {
  await database?.stop();
  if (process.connected) process.disconnect();
}
process.on(
  'message',
  (input: Start | { type: 'consume'; requestId: string; response: string } | { type: 'close' }) => {
    void (async () => {
      if (input.type === 'start') {
        if (started) throw new Error('The SAML worker was already started');
        started = true;
        phase = 'database-configuration';
        database = await createApplication({
          service: { name: 'saml-process-database', version: '1.0.0', environment: 'test' },
          plugins: [postgresPlugin()],
          databases: {
            main: { driver: 'postgresql', connectionStringEnv: 'DATABASE_URL', poolMax: 1 },
          },
        });
        phase = 'database-startup';
        await database.start();
        phase = 'state-provider';
        const replayStore = createPostgresSecurityStateStore(database.sql, 'main', input.schema);
        phase = 'saml-configuration';
        service = createSamlService({
          ...input.settings,
          replayStore,
          secretProvider: {
            async get(reference) {
              if (
                ![input.settings.signingKeyRef, input.settings.signingCertificateRef].includes(
                  reference,
                )
              )
                throw new Error('The ephemeral SAML key reference is unknown');
              return {
                bytes: Buffer.from(
                  reference === input.settings.signingKeyRef ? input.key : input.certificate,
                ),
                keyVersion: 'fixture',
              };
            },
          },
        });
        process.send?.({ type: 'ready' });
        return;
      }
      if (input.type === 'close') {
        await close();
        return;
      }
      if (!service || consuming) throw new Error('The SAML worker is not available');
      consuming = true;
      try {
        const identity = await service.consumeResponse(
          { inResponseTo: input.requestId, relayState: input.requestId },
          input.response,
        );
        process.send?.({
          type: 'result',
          result: identity.subject === 'synthetic-account' ? 'accepted' : 'unexpected-subject',
        });
      } catch (error) {
        process.send?.({
          type: 'result',
          result: error instanceof KitError ? error.code : 'unexpected-error',
        });
      }
    })().catch(async (error: unknown) => {
      const codes: string[] = [];
      for (
        let current = error, depth = 0;
        depth < 8 && current instanceof Error;
        depth++, current = current.cause
      )
        if (current instanceof KitError) codes.push(current.code);
      process.send?.({ type: 'failed', codes: [phase, ...codes] });
      process.exitCode = 1;
      await close();
    });
  },
);
process.once('disconnect', () => {
  void database?.stop().catch(() => {
    process.exitCode = 1;
  });
});
