// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const configuration = JSON.parse(globalThis.open(globalThis.__ENV.ARKENIVA_LOAD_CONFIG));
const https = configuration.https === true;
if (
  !(https ? /^https:\/\/localhost:\d+$/ : /^http:\/\/127\.0\.0\.1:\d+$/).test(configuration.origin)
)
  throw new Error('The load generator requires an owned loopback server');
const control = configuration.tlsControl;
if (control !== undefined && (!https || !['trusted', 'untrusted', 'wrong-name'].includes(control)))
  throw new Error('The HTTPS control selection is invalid');
const expectedError = control === 'untrusted' ? 1310 : control === 'wrong-name' ? 1311 : 0;
const names = https ? ['json'] : ['json', 'authenticated', 'database'];
const durations = Object.fromEntries(
  names.map((name) => [name, new Trend('latency_' + name, true)]),
);
const completions = Object.fromEntries(
  names.map((name) => [name, new Counter('completed_' + name)]),
);
const failures = new Counter('response_failures');
const tlsMetrics = https
  ? {
      http11: new Counter('observed_http11_responses'),
      tls13: new Counter('observed_tls13_responses'),
      handshake: new Trend('observed_tls_handshake_ms', true),
      connecting: new Trend('observed_tcp_connect_ms', true),
      positiveHandshake: new Counter('positive_handshake_duration_observations'),
      rejected: new Counter('expected_tls_rejections'),
      ciphers: Object.fromEntries(
        ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'].map(
          (value) => [value, new Counter('cipher_' + value)],
        ),
      ),
    }
  : undefined;
export const options = {
  scenarios: control
    ? {
        tls_control: {
          executor: 'shared-iterations',
          exec: 'json',
          vus: 1,
          iterations: 1,
          maxDuration: '10s',
        },
      }
    : Object.fromEntries(
        names.map((name) => [
          name,
          {
            executor: 'constant-arrival-rate',
            exec: name,
            rate: configuration.ratePerRoute,
            timeUnit: '1s',
            duration: configuration.durationSeconds + 's',
            preAllocatedVUs: 25,
            maxVUs: 25,
            gracefulStop: '10s',
          },
        ]),
      ),
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
  thresholds: {
    http_req_failed: [expectedError ? 'rate==1' : 'rate==0'],
    response_failures: ['count==0'],
    dropped_iterations: ['count==0'],
  },
  systemTags: ['method', 'name', 'scenario', 'status', 'expected_response'],
  maxRedirects: 0,
  ...(https
    ? {
        insecureSkipTLSVerify: false,
        tlsVersion: { min: http.TLS_1_3, max: http.TLS_1_3 },
        hosts: { localhost: '127.0.0.1', 'wrong.invalid': '127.0.0.1' },
      }
    : {}),
};
function request(name) {
  const origin =
    control === 'wrong-name'
      ? configuration.origin.replace('localhost', 'wrong.invalid')
      : configuration.origin;
  const reply = http.get(origin + '/' + name, {
    headers: name === 'json' ? {} : { authorization: 'Bearer ' + configuration.token },
    tags: { name: '/' + name },
    redirects: 0,
    timeout: '5s',
  });
  let valid = expectedError
    ? check(reply, {
        'TLS verification rejects the exact expected certificate failure': (value) =>
          value.status === 0 && value.error_code === expectedError,
      })
    : check(reply, {
        'status is 200': (value) => value.status === 200,
        'body is the exact expected 128 bytes': (value) =>
          value.body === configuration.expectedBody,
      });
  if (https) {
    if (expectedError)
      tlsMetrics.rejected.add(reply.status === 0 && reply.error_code === expectedError ? 1 : 0);
    else {
      valid =
        check(reply, {
          'HTTPS uses actual HTTP1.1': (value) => value.proto === 'HTTP/1.1',
          'HTTPS uses actual TLS1.3': (value) => value.tls_version === http.TLS_1_3,
          'HTTPS reports a supported actual TLS1.3 cipher': (value) =>
            Object.keys(tlsMetrics.ciphers).includes(value.tls_cipher_suite),
        }) && valid;
      tlsMetrics.http11.add(reply.proto === 'HTTP/1.1' ? 1 : 0);
      tlsMetrics.tls13.add(reply.tls_version === http.TLS_1_3 ? 1 : 0);
      tlsMetrics.handshake.add(reply.timings.tls_handshaking);
      tlsMetrics.connecting.add(reply.timings.connecting);
      tlsMetrics.positiveHandshake.add(reply.timings.tls_handshaking > 0 ? 1 : 0);
      for (const [cipher, metric] of Object.entries(tlsMetrics.ciphers))
        metric.add(reply.tls_cipher_suite === cipher ? 1 : 0);
    }
  }
  failures.add(valid ? 0 : 1);
  completions[name].add(1);
  durations[name].add(reply.timings.duration);
}
export function json() {
  request('json');
}
export function authenticated() {
  request('authenticated');
}
export function database() {
  request('database');
}
export function handleSummary(data) {
  return { [configuration.summaryPath]: JSON.stringify(data) };
}
