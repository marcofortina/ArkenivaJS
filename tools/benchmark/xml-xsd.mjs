// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, mkdtemp, readFile, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const xmlSchemaArtifacts = Object.freeze({
  invoice: Object.freeze({
    name: 'invoice.xsd',
    sha256: '842d992f4e7a310a8090f8cbf8579cb9767a4aa3346c9928be6ba048b3656e6b',
  }),
  invoiceTypes: Object.freeze({
    name: 'types.xsd',
    sha256: '730a58c04dc6412168cf6e4de70cb2eff2c20e0133fa26c52a25bdb295528597',
  }),
});
export const xmlNativeVersion = '2.9.14+dfsg-1.3ubuntu3.10';
const engine = '/usr/bin/xmllint',
  limiter = '/usr/bin/prlimit',
  query = '/usr/bin/dpkg-query';
const environment = Object.freeze({
  PATH: '/usr/bin:/bin',
  LANG: 'C.UTF-8',
  LC_ALL: 'C.UTF-8',
  XML_CATALOG_FILES: '',
  SGML_CATALOG_FILES: '',
});

/** Namespace membership is an inherited OS property; safe child environments need no marker. */
export async function assertXmlNamespace(expected) {
  assert.ok(
    process.platform === 'linux' && process.getuid?.() > 0,
    'Native XML smoke requires a non-root Linux namespace',
  );
  assert.deepEqual(
    Object.keys(networkInterfaces()),
    ['lo'],
    'Native XML smoke requires only the owned loopback interface',
  );
  const inode = (await stat('/proc/self/ns/net')).ino;
  assert.ok(Number.isSafeInteger(inode) && inode > 0);
  if (expected !== undefined)
    assert.equal(inode, expected, 'The XML worker left its owned network namespace');
  return inode;
}

async function identity(path) {
  const info = await lstat(path);
  assert.ok(
    info.isFile() &&
      !info.isSymbolicLink() &&
      info.uid === 0 &&
      !(info.mode & 0o022) &&
      info.mode & 0o111,
    'The native XML executable is not trusted',
  );
  return [info.dev, info.ino, info.size, info.mtimeMs, info.ctimeMs].join(':');
}

/** Drain bounded native diagnostics privately and wait for physical close, including on timeout. */
async function command(program, args, input, capture = false) {
  return new Promise((resolve, reject) => {
    let child,
      failed = false,
      bytes = 0,
      output = '';
    const timer = setTimeout(() => {
      failed = true;
      child?.kill('SIGKILL');
    }, 2000);
    try {
      child = spawn(program, args, { env: environment, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch {
      clearTimeout(timer);
      reject(new Error('The bounded native XML command could not start'));
      return;
    }
    child.once('error', () => {
      failed = true;
    });
    for (const stream of [child.stdout, child.stderr])
      stream.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 65536) {
          failed = true;
          child.kill('SIGKILL');
        } else if (capture) output += chunk.toString('utf8');
      });
    child.stdin.on('error', () => undefined);
    child.once('close', (code) => {
      clearTimeout(timer);
      if (failed) reject(new Error('The bounded native XML command failed'));
      else resolve({ code, output });
    });
    try {
      child.stdin.end(input);
    } catch {
      failed = true;
      child.kill('SIGKILL');
    }
  });
}

async function packages() {
  const result = await command(
    query,
    ['-W', '-f=${Package}\t${Version}\n', 'libxml2', 'libxml2-utils'],
    undefined,
    true,
  );
  assert.equal(result.code, 0, 'The reviewed XML packages are unavailable');
  assert.equal(
    result.output.trim().split('\n').sort().join('\n'),
    ['libxml2\t' + xmlNativeVersion, 'libxml2-utils\t' + xmlNativeVersion].sort().join('\n'),
    'The native XML package versions are not reviewed',
  );
}

export async function assertXmlAssets(configuration) {
  assert.ok(Number.isSafeInteger(configuration.namespaceInode) && configuration.namespaceInode > 0);
  await assertXmlNamespace(configuration.namespaceInode);
  for (const [id, artifact] of Object.entries(xmlSchemaArtifacts)) {
    const path = configuration.schemas[id],
      info = await lstat(path);
    assert.ok(
      info.isFile() &&
        !info.isSymbolicLink() &&
        info.uid === process.getuid() &&
        !(info.mode & 0o077) &&
        info.size > 0 &&
        info.size <= 4096,
    );
    assert.equal(await realpath(path), path);
    assert.equal(
      createHash('sha256')
        .update(await readFile(path))
        .digest('hex'),
      artifact.sha256,
      'The private XML schema artifact changed',
    );
  }
}

/** Create a private checked copy of the product-owned offline schema fixtures. */
export async function prepareXmlXsd() {
  const namespaceInode = await assertXmlNamespace();
  await Promise.all([engine, limiter, query].map(identity));
  await packages();
  const version = await command(engine, ['--version'], undefined, true);
  assert.ok(
    version.code === 0 &&
      /libxml version 20914\b/.test(version.output) &&
      /\bSchemas\b/.test(version.output),
    'The reviewed XSD engine is unavailable',
  );
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-benchmark-xml-xsd-'));
  try {
    const schemas = {};
    for (const [id, artifact] of Object.entries(xmlSchemaArtifacts)) {
      const source = await readFile(
        fileURLToPath(
          new URL('../../examples/xml/test/fixtures/' + artifact.name, import.meta.url),
        ),
      );
      assert.equal(
        createHash('sha256').update(source).digest('hex'),
        artifact.sha256,
        'The product XML schema artifact changed',
      );
      const path = join(directory, artifact.name);
      await writeFile(path, source, { flag: 'wx', mode: 0o600 });
      schemas[id] = path;
    }
    const configuration = { namespaceInode, schemas };
    await assertXmlAssets(configuration);
    return { configuration, close: () => rm(directory, { recursive: true, force: true }) };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}

/** Bare libxml2 XSD decisions, with the same fixed offline assets and finite native envelope. */
export async function nativeXsd(configuration) {
  await assertXmlAssets(configuration);
  const binding = await identity(engine);
  await Promise.all([limiter, query].map(identity));
  await packages();
  return async (input, id) => {
    assert.equal(id, 'invoice', 'Only the fixed offline invoice schema is benchmarked');
    assert.ok(input instanceof Uint8Array && input.byteLength > 0 && input.byteLength <= 4096);
    await assertXmlAssets(configuration);
    assert.equal(await identity(engine), binding, 'The native XML executable changed');
    await packages();
    const result = await command(
      limiter,
      [
        '--as=268435456',
        '--data=134217728',
        '--fsize=0',
        '--nofile=32',
        '--cpu=3',
        '--',
        engine,
        '--nonet',
        '--nocatalogs',
        '--nowarning',
        '--noout',
        '--schema',
        configuration.schemas.invoice,
        '-',
      ],
      input,
    );
    assert.ok(result.code === 0 || result.code === 3, 'Native XSD validation did not complete');
    return {
      valid: result.code === 0,
      messages:
        result.code === 0
          ? []
          : [
              {
                path: '',
                code: 'EK_XML_SCHEMA',
                message: 'The document does not satisfy the registered XML schema',
              },
            ],
    };
  };
}
