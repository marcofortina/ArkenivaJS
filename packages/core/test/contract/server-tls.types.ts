// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { ServerTlsFiles, HttpServerOptions, ApplicationOptions } from '../../dist/index.js';

function contract(files: ServerTlsFiles): void {
  const configured: ServerTlsFiles = {
    ...files,
    minVersion: 'TLSv1.3',
    clientCertificate: 'required',
    caFile: '/run/secrets/ca.pem',
  };
  // @ts-expect-error Legacy insecure TLS versions are outside the server policy.
  const insecure: ServerTlsFiles = { ...files, minVersion: 'TLSv1.1' };
  // @ts-expect-error File policy cannot contain raw key material.
  const plaintext: ServerTlsFiles = { ...files, key: 'private-material' };
  // @ts-expect-error Certificate references are immutable startup configuration.
  files.certificateFile = '/changed';
  void [configured, insecure, plaintext];
}
void contract;

function httpContracts(files: ServerTlsFiles, options: ApplicationOptions): void {
  const legacy: HttpServerOptions = { host: '127.0.0.1', port: 8080 };
  const plain: HttpServerOptions = { ...legacy, protocol: 'http' };
  const secure: HttpServerOptions = {
    protocol: 'https',
    host: '127.0.0.1',
    port: 8443,
    tls: files,
    http2: true,
  };
  const application: ApplicationOptions = { ...options, http: secure };
  // @ts-expect-error HTTPS must declare external TLS material.
  const missing: HttpServerOptions = { protocol: 'https', host: '127.0.0.1', port: 8443 };
  // @ts-expect-error Plain HTTP never accepts TLS settings.
  const ambiguous: HttpServerOptions = {
    protocol: 'http',
    host: '127.0.0.1',
    port: 8080,
    tls: files,
  };
  // @ts-expect-error HTTP/2 without TLS is outside the public contract, including false placeholders.
  const h2c: HttpServerOptions = { protocol: 'http', host: '127.0.0.1', port: 8080, http2: false };
  void [legacy, plain, secure, application, missing, ambiguous, h2c];
}
void httpContracts;
