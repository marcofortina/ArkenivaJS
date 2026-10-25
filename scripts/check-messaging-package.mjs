import assert from 'node:assert/strict';
import { mkdtemp, chmod, readFile, writeFile, copyFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-message-package-'));
await chmod(directory, 0o700);
function execute(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit', timeout: 120000 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, 'Packed messaging consumer verification failed');
}
try {
  for (const name of ['core', 'messaging']) {
    execute('pnpm', ['pack', '--pack-destination', directory], join(root, 'packages', name));
  }
  const core = 'file:' + join(directory, 'arkenivajs-core-0.1.0.tgz');
  await writeFile(
    join(directory, 'package.json'),
    JSON.stringify({
      name: 'messaging-package-verification',
      private: true,
      type: 'module',
      dependencies: {
        '@arkenivajs/core': core,
        '@arkenivajs/messaging': 'file:' + join(directory, 'arkenivajs-messaging-0.1.0.tgz'),
      },
    }),
  );
  await writeFile(
    join(directory, 'pnpm-workspace.yaml'),
    "packages: []\noverrides:\n  '@arkenivajs/core': " + JSON.stringify(core) + '\n',
  );
  execute('pnpm', ['install', '--ignore-scripts'], directory);
  const require = createRequire(
    await realpath(join(directory, 'node_modules/@arkenivajs/messaging/package.json')),
  );
  const sdk = dirname(require.resolve('nats/package.json'));
  const declarations = await readFile(join(sdk, 'lib/nats-base-client/core.d.ts'), 'utf8');
  assert.ok(!declarations.includes('Declaration-only compatibility correction'));
  assert.match(declarations, /info\?: ServerInfo;/);
  assert.match(declarations, /headers\?: MsgHdrs;/);
  await copyFile(
    join(root, 'packages/messaging/test/fixtures/portable-consumer.ts'),
    join(directory, 'consumer.ts'),
  );
  execute(
    process.execPath,
    [
      join(root, 'node_modules/typescript/bin/tsc'),
      '--ignoreConfig',
      '--strict',
      '--exactOptionalPropertyTypes',
      '--noUncheckedIndexedAccess',
      '--useUnknownInCatchVariables',
      '--skipLibCheck',
      'false',
      '--target',
      'ES2023',
      '--module',
      'NodeNext',
      '--moduleResolution',
      'NodeNext',
      '--noEmit',
      'consumer.ts',
    ],
    directory,
  );
  execute(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      'const module = await import("@arkenivajs/messaging"); if(typeof module.messagingPlugin!=="function"||typeof module.createNatsBus!=="function")throw new Error("Missing portable messaging exports");',
    ],
    directory,
  );
  console.log(
    'Packed messaging exports compile strictly and import with the unpatched native SDK.',
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}
