// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { readFile, writeFile, stat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { startServer } from '../../dist-test/unit/server.js';

if (process.argv.length !== 4 || process.argv[2] !== '--test-only' || !isAbsolute(process.argv[3]))
  throw new Error('An explicit owned OAuth test fixture directory is required');
const directory = process.argv[3],
  info = await stat(directory);
if (!info.isDirectory() || (info.mode & 0o077) !== 0)
  throw new Error('The OAuth fixture directory must be private');
const server = await startServer({
  key: await readFile(join(directory, 'server.key')),
  cert: await readFile(join(directory, 'server.crt')),
});
let closing;
const close = () => {
  closing ??= server.close().then(() => {
    process.exitCode = 0;
  });
};
process.once('SIGTERM', close);
process.once('SIGINT', close);
try {
  await writeFile(
    join(directory, 'runtime.json'),
    JSON.stringify({
      issuer: server.issuer,
      clientId: server.clientId,
      clientSecret: server.secret,
      redirectUri: server.redirectUri,
      audience: server.audience,
    }),
    { flag: 'wx', mode: 0o600 },
  );
  process.stdout.write('Owned HTTPS OAuth fixture ready\n');
} catch {
  await server.close();
  throw new Error('The private OAuth fixture metadata could not be written');
}
