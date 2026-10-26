// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, createServer } from 'node:tls';
import type { TLSSocket } from 'node:tls';
import type { MtlsTrustProvider, X509PluginSettings } from '@arkenivajs/security-x509';

/** Real disposable CA, intermediate, CRLs and TLS handshake; keys never enter the repository. */
export async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-x509-'));
  await chmod(directory, 0o700);
  const path = (name: string) => join(directory, name);
  const openssl = (...args: string[]) =>
    execFileSync('openssl', args, { cwd: directory, stdio: 'ignore', timeout: 10000 });
  const sockets = new Set<TLSSocket>();
  let server: ReturnType<typeof createServer> | undefined, privateKey: Buffer | undefined;
  try {
    for (const name of ['root', 'intermediate', 'foreign']) {
      openssl(
        'req',
        '-new',
        ...(name === 'intermediate'
          ? []
          : [
              '-x509',
              '-days',
              '3',
              '-addext',
              'basicConstraints=critical,CA:TRUE,pathlen:1',
              '-addext',
              'keyUsage=critical,keyCertSign,cRLSign',
            ]),
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-subj',
        '/CN=' + name,
        '-keyout',
        name + '.key',
        '-out',
        name + (name === 'intermediate' ? '.csr' : '.pem'),
      );
      await chmod(path(name + '.key'), 0o600);
    }
    for (const name of ['root', 'intermediate']) {
      await mkdir(path(name + '-issued'));
      await writeFile(path(name + '.db'), '', { mode: 0o600 });
      await writeFile(path(name + '.serial'), '1000\n', { mode: 0o600 });
      await writeFile(path(name + '.crlnumber'), '1000\n', { mode: 0o600 });
      await writeFile(
        path(name + '.ini'),
        `[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=${name}.db\nnew_certs_dir=${name}-issued\nserial=${name}.serial\ncrlnumber=${name}.crlnumber\ncertificate=${name}.pem\nprivate_key=${name}.key\ndefault_md=sha256\ndefault_days=2\ndefault_crl_days=1\npolicy=subject_policy\nunique_subject=no\n[subject_policy]\ncommonName=supplied\n[ca_extensions]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n[leaf_extensions]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\nsubjectAltName=@names\n[names]\nDNS.1=localhost\nIP.1=127.0.0.1\nURI.1=spiffe://fixture/service\nURI.2="https://fixture.invalid/path, DNS:forged.invalid"\n[cn_extensions]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n`,
        { mode: 0o600 },
      );
    }
    openssl(
      'ca',
      '-batch',
      '-config',
      'root.ini',
      '-extensions',
      'ca_extensions',
      '-in',
      'intermediate.csr',
      '-out',
      'intermediate.pem',
      '-notext',
    );
    for (const name of ['leaf', 'expired', 'future', 'cn']) {
      openssl(
        'req',
        '-new',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-subj',
        '/CN=localhost',
        '-keyout',
        name + '.key',
        '-out',
        name + '.csr',
      );
      await chmod(path(name + '.key'), 0o600);
      const dates =
        name === 'expired'
          ? ['-startdate', '20200101000000Z', '-enddate', '20200102000000Z']
          : name === 'future'
            ? ['-startdate', '20990101000000Z', '-enddate', '20990102000000Z']
            : [];
      openssl(
        'ca',
        '-batch',
        '-config',
        'intermediate.ini',
        '-extensions',
        name === 'cn' ? 'cn_extensions' : 'leaf_extensions',
        '-in',
        name + '.csr',
        '-out',
        name + '.pem',
        '-notext',
        ...dates,
      );
    }
    for (const name of ['root', 'intermediate'])
      openssl('ca', '-config', name + '.ini', '-gencrl', '-out', name + '.crl');
    openssl(
      'x509',
      '-in',
      'root.pem',
      '-signkey',
      'root.key',
      '-days',
      '-1',
      '-out',
      'expired-root.pem',
    );
    const pem = await readFile(path('leaf.pem')),
      intermediate = await readFile(path('intermediate.pem')),
      root = await readFile(path('root.pem')),
      foreign = await readFile(path('foreign.pem'));
    const der = (input: Uint8Array) => new X509Certificate(input).raw;
    const chain = [der(pem), der(intermediate)],
      roots = [der(root)];
    privateKey = await readFile(path('leaf.key'));
    server = createServer(
      {
        key: privateKey,
        cert: Buffer.concat([pem, intermediate]),
        minVersion: 'TLSv1.2',
        handshakeTimeout: 1000,
      },
      (socket) => {
        socket.end();
      },
    );
    server.on('connection', (socket) => {
      sockets.add(socket as TLSSocket);
      socket.once('close', () => sockets.delete(socket as TLSSocket));
    });
    server.on('tlsClientError', () => {});
    await new Promise<void>((resolve, reject) => {
      server!.once('error', reject);
      server!.listen(0, '127.0.0.1', () => {
        server!.off('error', reject);
        resolve();
      });
    });
    const address = server.address();
    if (!address || typeof address === 'string')
      throw new Error('Disposable TLS address unavailable');
    let calls = 0,
      available = true,
      lastSignal: AbortSignal | undefined;
    const provider: MtlsTrustProvider & { readonly usage: 'test-only' } = {
      usage: 'test-only',
      async verifyChainAndRevocation(input, options) {
        calls++;
        lastSignal = options?.signal;
        if (!available || input.policy.trustRootsRef !== 'fixture')
          throw new Error('Disposable trust checker unavailable');
        const crl = await Promise.all(
          ['root', 'intermediate'].map((name) => readFile(path(name + '.crl'))),
        );
        return new Promise((resolve, reject) => {
          const socket = connect(
            {
              host: '127.0.0.1',
              port: address.port,
              servername: 'localhost',
              ca: [root],
              crl,
              rejectUnauthorized: true,
              minVersion: 'TLSv1.2',
              ...(options?.signal ? { signal: options.signal } : {}),
              timeout: options?.timeoutMs ?? 1000,
            },
            () => {
              try {
                const certificate = new X509Certificate(socket.getPeerCertificate().raw);
                if (!socket.authorized || !certificate.raw.equals(Buffer.from(input.peerDer)))
                  throw new Error('Disposable TLS peer mismatch');
                resolve({
                  uriSans: [
                    'spiffe://fixture/service',
                    'https://fixture.invalid/path, DNS:forged.invalid',
                  ],
                  dnsSans: ['localhost'],
                  certificateFingerprintSha256: certificate.fingerprint256,
                  issuer: certificate.issuer,
                  notAfter: certificate.validToDate.toISOString(),
                });
              } catch (error) {
                reject(error);
              } finally {
                socket.destroy();
              }
            },
          );
          socket.once('timeout', () =>
            socket.destroy(new Error('Disposable TLS verification timed out')),
          );
          socket.once('error', reject);
        });
      },
    };
    const settings: X509PluginSettings = {
      trustRoots: { fixture: roots },
      trustProvider: provider,
      policy: { maxConcurrent: 4, timeoutMs: 2000 },
    };
    return {
      settings,
      provider,
      pem,
      chain,
      roots,
      foreign: der(foreign),
      expired: der(await readFile(path('expired.pem'))),
      future: der(await readFile(path('future.pem'))),
      cn: der(await readFile(path('cn.pem'))),
      expiredRoot: der(await readFile(path('expired-root.pem'))),
      calls: () => calls,
      lastSignal: () => lastSignal,
      unavailable(value: boolean) {
        available = !value;
      },
      async revoke() {
        openssl('ca', '-config', 'intermediate.ini', '-revoke', 'leaf.pem');
        openssl('ca', '-config', 'intermediate.ini', '-gencrl', '-out', 'intermediate.crl');
      },
      async close() {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>((resolve) => server!.close(() => resolve()));
        privateKey?.fill(0);
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    for (const socket of sockets) socket.destroy();
    if (server?.listening) await new Promise<void>((resolve) => server!.close(() => resolve()));
    privateKey?.fill(0);
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
