// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect, createServer } from 'node:tls';
import type { TLSSocket } from 'node:tls';
import { KitError } from '@arkenivajs/core';
import type { MtlsTrustProvider } from '@arkenivajs/security-x509';

const unavailable = () =>
  new KitError({
    code: 'EK_X509_UNTRUSTED',
    message: 'The disposable certificate verifier is unavailable',
  });

/** Test-only CA and endpoint ownership; public certificate bytes contain no private key material. */
export interface CertificateFixture {
  readonly provider: MtlsTrustProvider;
  readonly rootDer: Uint8Array;
  readonly leafDer: Uint8Array;
  readonly leafPem: string;
  checks(): number;
  revoke(): Promise<void>;
  close(): Promise<void>;
}

/** Generate one private disposable CA and verify its TLS endpoint with actual native CRL checks. */
export async function createCertificateFixture(authorization: {
  readonly testOnly: true;
}): Promise<CertificateFixture> {
  if (authorization?.testOnly !== true)
    throw new KitError({
      code: 'EK_CONFIG_INVALID',
      message: 'Explicit disposable certificate fixture authorization is required',
    });
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-certificates-'));
  await chmod(directory, 0o700);
  const path = (name: string) => join(directory, name);
  const openssl = (...args: string[]) =>
    execFileSync('openssl', args, { cwd: directory, stdio: 'ignore', timeout: 10000 });
  const clients = new Set<TLSSocket>(),
    accepted = new Set<TLSSocket>();
  let server: ReturnType<typeof createServer> | undefined,
    privateKey: Buffer | undefined,
    closed = false,
    active = 0,
    checks = 0;
  try {
    openssl(
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-days',
      '2',
      '-subj',
      '/CN=Disposable certificate authority',
      '-addext',
      'basicConstraints=critical,CA:TRUE,pathlen:0',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
      '-keyout',
      'root.key',
      '-out',
      'root.pem',
    );
    await chmod(path('root.key'), 0o600);
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
      'leaf.key',
      '-out',
      'leaf.csr',
    );
    await chmod(path('leaf.key'), 0o600);
    await mkdir(path('issued'), { mode: 0o700 });
    await writeFile(path('index'), '', { mode: 0o600 });
    await writeFile(path('serial'), '1000\n', { mode: 0o600 });
    await writeFile(path('crlnumber'), '1000\n', { mode: 0o600 });
    await writeFile(
      path('ca.ini'),
      '[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index\nnew_certs_dir=issued\nserial=serial\ncrlnumber=crlnumber\ncertificate=root.pem\nprivate_key=root.key\ndefault_md=sha256\ndefault_days=1\ndefault_crl_days=1\npolicy=subject\n[subject]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n',
      { mode: 0o600 },
    );
    openssl(
      'ca',
      '-batch',
      '-config',
      'ca.ini',
      '-extensions',
      'leaf',
      '-in',
      'leaf.csr',
      '-out',
      'leaf.pem',
      '-notext',
    );
    openssl('ca', '-config', 'ca.ini', '-gencrl', '-out', 'root.crl');
    const rootPem = await readFile(path('root.pem')),
      leafPem = await readFile(path('leaf.pem'), 'utf8');
    const certificate = new X509Certificate(leafPem),
      leafDer = certificate.raw,
      rootDer = new X509Certificate(rootPem).raw;
    privateKey = await readFile(path('leaf.key'));
    server = createServer(
      { key: privateKey, cert: leafPem, minVersion: 'TLSv1.2', handshakeTimeout: 1000 },
      (socket) => socket.end(),
    );
    server.on('connection', (socket) => {
      accepted.add(socket as TLSSocket);
      socket.once('close', () => accepted.delete(socket as TLSSocket));
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
    if (!address || typeof address === 'string') throw unavailable();
    const provider: MtlsTrustProvider & { readonly usage: 'test-only' } = {
      usage: 'test-only',
      async verifyChainAndRevocation(input, options) {
        const timeoutMs = options?.timeoutMs ?? 2000;
        if (
          closed ||
          active >= 4 ||
          !Number.isSafeInteger(timeoutMs) ||
          timeoutMs < 1 ||
          timeoutMs > 10000 ||
          input.policy.trustRootsRef !== 'demonstration' ||
          input.policy.hostname !== 'localhost' ||
          input.policy.revocation !== 'approved-online-checker' ||
          input.policy.allowedIdentities.length !== 1 ||
          input.policy.allowedIdentities[0] !== 'localhost' ||
          !(input.peerDer instanceof Uint8Array) ||
          input.peerDer.byteLength > 65536 ||
          !Buffer.from(input.peerDer).equals(leafDer)
        )
          throw unavailable();
        active++;
        checks++;
        try {
          const crl = await readFile(path('root.crl'));
          if (closed || crl.length > 16384) throw unavailable();
          return await new Promise((resolve, reject) => {
            const socket = connect(
              {
                host: '127.0.0.1',
                port: address.port,
                servername: 'localhost',
                ca: [rootPem],
                crl,
                rejectUnauthorized: true,
                minVersion: 'TLSv1.2',
                timeout: timeoutMs,
                ...(options?.signal ? { signal: options.signal } : {}),
              },
              () => {
                try {
                  const peer = new X509Certificate(socket.getPeerCertificate().raw);
                  if (!socket.authorized || !peer.raw.equals(leafDer)) throw unavailable();
                  resolve(
                    Object.freeze({
                      dnsSans: Object.freeze(['localhost']),
                      uriSans: Object.freeze([]),
                      certificateFingerprintSha256: peer.fingerprint256,
                      issuer: peer.issuer,
                      notAfter: peer.validToDate.toISOString(),
                    }),
                  );
                } catch {
                  reject(unavailable());
                } finally {
                  socket.destroy();
                }
              },
            );
            clients.add(socket);
            socket.once('close', () => clients.delete(socket));
            socket.once('timeout', () => socket.destroy(unavailable()));
            socket.once('error', () => reject(unavailable()));
          });
        } catch {
          throw unavailable();
        } finally {
          active--;
        }
      },
    };
    return {
      provider,
      rootDer,
      leafDer,
      leafPem,
      checks: () => checks,
      async revoke() {
        if (closed) throw unavailable();
        openssl('ca', '-config', 'ca.ini', '-revoke', 'leaf.pem');
        openssl('ca', '-config', 'ca.ini', '-gencrl', '-out', 'root.crl');
      },
      async close() {
        if (closed) return;
        closed = true;
        for (const socket of [...clients, ...accepted]) socket.destroy();
        await new Promise<void>((resolve) => server!.close(() => resolve()));
        privateKey?.fill(0);
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    closed = true;
    for (const socket of [...clients, ...accepted]) socket.destroy();
    if (server?.listening) await new Promise<void>((resolve) => server!.close(() => resolve()));
    privateKey?.fill(0);
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
