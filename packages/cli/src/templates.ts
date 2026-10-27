// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { LICENSE_TEXT } from './legal-text.js';

const header =
  '// SPDX-License-Identifier: AGPL-3.0-or-later\n// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>\n\n';
/** A small explicit plugin composition, without database or outbound transport dependencies. */
export function templates(name: string, version: string): ReadonlyMap<string, string> {
  const manifest = {
    name,
    version: '1.0.0',
    private: true,
    type: 'module',
    engines: { node: '^22.23.4 || ^24.22.1 || ^26.12.1' },
    packageManager: 'pnpm@12.15.0',
    scripts: {
      build: 'tsc -p tsconfig.json',
      start: 'node dist/main.js',
      typecheck: 'tsc -p tsconfig.json --noEmit',
    },
    dependencies: {
      '@arkenivajs/api': version,
      '@arkenivajs/core': version,
      '@arkenivajs/logging': version,
    },
    devDependencies: { '@types/node': '22.20.5', typescript: '6.0.3' },
    license: 'AGPL-3.0-or-later',
  };
  return new Map([
    [
      'src/main.ts',
      header +
        `import { createApplication, KitError } from '@arkenivajs/core';
import { apiPlugin } from '@arkenivajs/api';
import { loggingPlugin } from '@arkenivajs/logging';

/** Create a loopback development service; register protected business routes explicitly. */
export async function createService(port = 8080) {
  const app = await createApplication({
    service: { name: '${name}', version: '1.0.0', environment: 'development' },
    http: { host: '127.0.0.1', port },
    logging: { level: 'info' },
    plugins: [loggingPlugin(), apiPlugin()],
  });
  app.api.get('/hello', {
    schema: {
      response: {
        type: 'object', properties: { greeting: { type: 'string' } },
        required: ['greeting'], additionalProperties: false,
      },
    },
    auth: { required: false },
    handler: () => ({ greeting: 'Hello from ${name}' }),
  });
  return app;
}

export async function main() {
  const app = await createService();
  await app.start();
  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    process.off('SIGINT', stop);
    process.off('SIGTERM', stop);
    void app.stop().catch(() => {
      console.error('The service could not stop cleanly');
      process.exitCode = 1;
    });
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}

import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  void main().catch((error: unknown) => {
    console.error(error instanceof KitError ? error.toSafeJSON() : { message: 'The service could not start' });
    process.exitCode = 1;
  });
}
`,
    ],
    [
      'tsconfig.json',
      JSON.stringify(
        {
          compilerOptions: {
            target: 'ES2023',
            module: 'NodeNext',
            moduleResolution: 'NodeNext',
            strict: true,
            noUncheckedIndexedAccess: true,
            exactOptionalPropertyTypes: true,
            verbatimModuleSyntax: true,
            declaration: true,
            rootDir: 'src',
            outDir: 'dist',
            types: ['node'],
          },
          include: ['src/**/*.ts'],
        },
        null,
        2,
      ) + '\n',
    ],
    [
      '.gitignore',
      '# SPDX-License-Identifier: AGPL-3.0-or-later\n# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>\n\nnode_modules/\ndist/\n.env\n.env.*\n*.patch\n.arkenivajs.lock\n.arkenivajs-manifest-*.tmp\n',
    ],
    [
      'README.md',
      `# ${name}\n\nInstall the exact declared framework versions after their approved publication, then run:\n\n\`\`\`sh\npnpm install\npnpm build\npnpm start\n\`\`\`\n\nOpen \`http://127.0.0.1:8080/hello\`. This public greeting is a local development example. Configure authentication, TLS or a trusted ingress, and deployment policy before exposing business routes.\n\n\`arkenivajs add <module>\` changes only the selected dependency. Import and configure its documented plugin explicitly before startup. No driver is installed or activated automatically.\n\nThe starter source uses AGPL-3.0-or-later SPDX notices. Review the applicable framework license and preserve required notices when distributing modified code.\n`,
    ],
    ['LICENSE', LICENSE_TEXT],
    ['package.json', JSON.stringify(manifest, null, 2) + '\n'],
  ]);
}
