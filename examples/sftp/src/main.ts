// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createApplication } from '@arkenivajs/core';
import { sftpPlugin, SFTP_CAPABILITY, SSH_CAPABILITY } from '@arkenivajs/sftp';
import type { SftpPluginSettings, SftpService, SshService } from '@arkenivajs/sftp';

/** The caller supplies a deployment-owned profile and secret authority; requests never choose hosts. */
export async function runSftpExample(settings: SftpPluginSettings, directory: string) {
  const connection = settings.connections[0]?.name;
  if (!connection) throw new Error('An approved SFTP profile is required');
  const app = await createApplication({
    service: { name: 'sftp-example', version: '0.1.0', environment: 'test' },
    plugins: [sftpPlugin(settings)],
  });
  try {
    await app.start();
    const sftp = app.resolve<SftpService>(SFTP_CAPABILITY),
      ssh = app.resolve<SshService>(SSH_CAPABILITY),
      path = directory + '/example-' + randomUUID();
    async function* source() {
      yield Buffer.from('ArkenivaJS transfer\n');
    }
    const uploaded = await sftp.upload(connection, source(), path),
      parts: Uint8Array[] = [],
      downloaded = await sftp.download(connection, path, async (part) => {
        parts.push(part);
      }),
      renamed = await sftp.rename(connection, path, path + '.ready', {
        overwrite: 'replace',
        requireAtomic: true,
      }),
      command = await ssh.exec(connection, 'report', { value: 'complete' });
    return { uploaded, downloaded, renamed, text: Buffer.concat(parts).toString('utf8'), command };
  } finally {
    await app.stop();
  }
}
/** Read only private local fixture metadata; production applications use their secure secret provider. */
export async function fixtureSettings() {
  const path = process.env.ARKENIVA_SFTP_FIXTURE;
  if (!path) throw new Error('The owned OpenSSH fixture metadata path is required');
  const value = JSON.parse(await readFile(path, 'utf8')) as {
    host: string;
    port: number;
    username: string;
    privateKeyFile: string;
    pins: string[];
    root: string;
  };
  const key = await readFile(value.privateKeyFile);
  const settings: SftpPluginSettings = {
    connections: [
      {
        name: 'fixture',
        host: value.host,
        port: value.port,
        username: value.username,
        privateKeyRef: 'fixture-key',
        knownHostSha256: value.pins,
        allowedRemoteRoots: [value.root],
      },
    ],
    secretProvider: {
      async get() {
        return { bytes: key, keyVersion: 'fixture-version' };
      },
    },
    allowedCommands: { report: { executable: '/usr/bin/printf', arguments: ['%s', '{value}'] } },
    policy: { maxConcurrent: 1, timeoutMs: 10000, maxInputBytes: 1048576, maxOutputBytes: 1048576 },
  };
  return { settings, directory: value.root, clear: () => key.fill(0) };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const fixture = await fixtureSettings();
  try {
    const result = await runSftpExample(fixture.settings, fixture.directory);
    console.log(
      JSON.stringify({
        transferredBytes: result.uploaded.transferredBytes,
        atomicity: result.renamed.atomicity,
        exitCode: result.command.exitCode,
      }),
    );
  } finally {
    fixture.clear();
  }
}
