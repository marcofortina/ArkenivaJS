// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { runPureWorker } from './pure-worker.mjs';
import { nativeMail, mailSettings, verifyMail } from './mail-workload.mjs';
runPureWorker({
  name: 'mail',
  native: nativeMail,
  async framework(fixture) {
    const { mailPlugin, MAIL_CAPABILITY } = await import('@arkenivajs/mail');
    return { plugin: mailPlugin(mailSettings(fixture)), key: MAIL_CAPABILITY };
  },
  verify: verifyMail,
  close: (service) => service.close(),
});
