// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { execFile, execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type {
  MtlsCredentialProvider,
  MtlsPluginSettings,
  MtlsTrustProvider,
  TlsMaterial,
  TlsProfile,
} from '@arkenivajs/security-mtls';

const execute = promisify(execFile);
/** Separate signed server/client credentials, actual CRLs and a complete external PKI verifier. */
export async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'arkenivajs-mtls-'));
  await chmod(directory, 0o700);
  const path = (name: string) => join(directory, name),
    openssl = (...args: string[]) =>
      execFileSync('openssl', args, { cwd: directory, stdio: 'ignore', timeout: 10000 });
  const ownedKeys = new Set<Buffer>(),
    materials = new Map<string, TlsMaterial>(),
    certificates = new Map<
      string,
      {
        certificate: X509Certificate;
        name: string;
        dnsSans: readonly string[];
        uriSans: readonly string[];
      }
    >();
  try {
    for (const name of ['root', 'foreign']) {
      openssl(
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-days',
        '3',
        '-subj',
        '/CN=' + name,
        '-addext',
        'basicConstraints=critical,CA:TRUE,pathlen:0',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
        '-keyout',
        name + '.key',
        '-out',
        name + '.pem',
      );
      await chmod(path(name + '.key'), 0o600);
    }
    await mkdir(path('issued'), { mode: 0o700 });
    for (const [name, content] of [
      ['index', ''],
      ['serial', '1000\n'],
      ['crlnumber', '1000\n'],
    ])
      await writeFile(path(name!), content!, { mode: 0o600 });
    const root = await readFile(path('root.pem'));
    for (const name of [
      'server',
      'rotated',
      'client',
      'expired',
      'future',
      'server-only',
      'client-only',
      'cn',
    ]) {
      const identity = name === 'client' || name === 'client-only' ? 'client' : 'server';
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
      const config = `[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=index\nnew_certs_dir=issued\nserial=serial\ncrlnumber=crlnumber\ncertificate=root.pem\nprivate_key=root.key\ndefault_md=sha256\ndefault_days=2\ndefault_crl_days=1\npolicy=subject\nunique_subject=no\n[subject]\ncommonName=supplied\n[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=${name === 'server-only' ? 'serverAuth' : name === 'client-only' ? 'clientAuth' : 'serverAuth,clientAuth'}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n${name === 'cn' ? '' : `subjectAltName=DNS:localhost,IP:127.0.0.1,URI:spiffe://fixture/${identity}\n`}`;
      await writeFile(path('ca.ini'), config, { mode: 0o600 });
      openssl(
        'ca',
        '-batch',
        '-config',
        'ca.ini',
        '-extensions',
        'leaf',
        '-in',
        name + '.csr',
        '-out',
        name + '.pem',
        '-notext',
        ...(name === 'expired'
          ? ['-startdate', '20200101000000Z', '-enddate', '20200102000000Z']
          : name === 'future'
            ? ['-startdate', '20990101000000Z', '-enddate', '20990102000000Z']
            : []),
      );
      const cert = await readFile(path(name + '.pem')),
        key = await readFile(path(name + '.key')),
        certificate = new X509Certificate(cert);
      ownedKeys.add(key);
      materials.set(name, { ca: [root], cert, key, minVersion: 'TLSv1.3', ALPNProtocols: ['h2'] });
      certificates.set(certificate.fingerprint256, {
        certificate,
        name,
        dnsSans: name === 'cn' ? [] : ['localhost'],
        uriSans: name === 'cn' ? [] : ['spiffe://fixture/' + identity],
      });
    }
    openssl('ca', '-config', 'ca.ini', '-gencrl', '-out', 'root.crl');
    const profiles: Record<string, TlsProfile> = Object.fromEntries(
      ['server', 'client'].map((name) => [
        name,
        {
          trustRootsRef: 'fixture',
          certRef: name + '-certificate',
          keyRef: name + '-key',
          allowedIdentities: ['spiffe://fixture/' + (name === 'server' ? 'client' : 'server')],
          minTlsVersion: 'TLSv1.3',
          alpnProtocols: ['h2'],
          revocation: 'crl-required',
        },
      ]),
    );
    let unavailable = false,
      loads = 0,
      verifications = 0;
    const credentialProvider: MtlsCredentialProvider & { readonly usage: 'test-only' } = {
      usage: 'test-only',
      async load(profile, options) {
        loads++;
        if (unavailable || options?.signal?.aborted)
          throw new Error('Private credential provider unavailable');
        const name =
          profile.certRef === 'server-certificate'
            ? 'server'
            : profile.certRef === 'client-certificate'
              ? 'client'
              : undefined;
        if (!name) throw new Error('Unapproved fixture reference');
        return materials.get(name)!;
      },
    };
    const trustProvider: MtlsTrustProvider & { readonly usage: 'test-only' } = {
      usage: 'test-only',
      async verifyChainAndRevocation(input, options) {
        verifications++;
        if (
          unavailable ||
          input.policy.trustRootsRef !== 'fixture' ||
          input.policy.revocation !== 'crl-required'
        )
          throw new Error('Private revocation service unavailable');
        const certificate = new X509Certificate(input.peerDer),
          known = certificates.get(certificate.fingerprint256);
        if (!known) throw new Error('Unapproved fixture certificate');
        await execute(
          'openssl',
          [
            'verify',
            '-CAfile',
            path('root.pem'),
            '-CRLfile',
            path('root.crl'),
            '-crl_check_all',
            '-purpose',
            known.name === 'client' || known.name === 'client-only' ? 'sslclient' : 'sslserver',
            path(known.name + '.pem'),
          ],
          {
            timeout: options?.timeoutMs ?? 1000,
            ...(options?.signal ? { signal: options.signal } : {}),
            maxBuffer: 16384,
          },
        );
        return {
          dnsSans: known.dnsSans,
          uriSans: known.uriSans,
          certificateFingerprintSha256: certificate.fingerprint256,
          issuer: certificate.issuer,
          notAfter: certificate.validToDate.toISOString(),
        };
      },
    };
    const settings: MtlsPluginSettings = {
      profiles,
      credentialProvider,
      trustProvider,
      reloadMode: 'explicit',
      policy: { maxConcurrent: 4, timeoutMs: 3000 },
    };
    return {
      settings,
      materials,
      certificates,
      profiles,
      credentialProvider,
      trustProvider,
      root,
      foreign: await readFile(path('foreign.pem')),
      loads: () => loads,
      verifications: () => verifications,
      unavailable(value: boolean) {
        unavailable = value;
      },
      async revoke(name: 'server' | 'client') {
        openssl('ca', '-config', 'ca.ini', '-revoke', name + '.pem');
        openssl('ca', '-config', 'ca.ini', '-gencrl', '-out', 'root.crl');
      },
      async close() {
        for (const value of ownedKeys) value.fill(0);
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    for (const value of ownedKeys) value.fill(0);
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
