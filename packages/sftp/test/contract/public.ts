// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { sftpPlugin, SFTP_CAPABILITY, SSH_CAPABILITY } from '../../dist/index.js';
import type {
  SftpPluginSettings,
  SftpService,
  SshService,
  SftpRenameReceipt,
} from '../../dist/index.js';
export function contracts(
  settings: SftpPluginSettings,
  sftp: SftpService,
  ssh: SshService,
  receipt: SftpRenameReceipt,
) {
  const native: unknown = sftp.native('partner');
  // @ts-expect-error Native instances require deliberate consumer-side narrowing.
  native.connect({ host: 'untrusted.invalid' });
  // @ts-expect-error A required atomic rename is an explicit boolean, never a string.
  sftp.rename('partner', '/incoming/source', '/incoming/target', { requireAtomic: 'yes' });
  // @ts-expect-error Remote command text is not an accepted method.
  ssh.shell('partner', 'untrusted');
  // @ts-expect-error Transfer receipts are immutable.
  receipt.atomicity = 'confirmed';
  return { plugin: sftpPlugin(settings), keys: [SFTP_CAPABILITY, SSH_CAPABILITY], native };
}
