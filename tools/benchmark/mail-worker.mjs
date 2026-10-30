// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { runPureWorker } from './pure-worker.mjs';
import {
  nativeMail,
  mailSettings,
  verifyMail,
  mailWorkload,
  mailObservations,
} from './mail-workload.mjs';
export const mailAdapter = {
  name: 'mail',
  asynchronous: true,
  iterations: 100,
  warmupIterations: 20,
  retainRawSamples: true,
  native: nativeMail,
  async framework(fixture) {
    const { mailPlugin, MAIL_CAPABILITY } = await import('@arkenivajs/mail');
    return { plugin: mailPlugin(mailSettings(fixture)), key: MAIL_CAPABILITY };
  },
  verify: verifyMail,
  workload: mailWorkload,
  complete: mailObservations,
  close: (service) => service.close(),
};

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  runPureWorker(mailAdapter);
