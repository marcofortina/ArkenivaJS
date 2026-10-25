// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';

const configuration = JSON.parse(globalThis.open(globalThis.__ENV.ARKENIVA_LOAD_CONFIG));
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(configuration.origin))
  throw new Error('The load generator requires an owned loopback server');
const names = ['json', 'authenticated', 'database'];
const durations = Object.fromEntries(
  names.map((name) => [name, new Trend('latency_' + name, true)]),
);
const completions = Object.fromEntries(
  names.map((name) => [name, new Counter('completed_' + name)]),
);
const failures = new Counter('response_failures');
export const options = {
  scenarios: Object.fromEntries(
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
    http_req_failed: ['rate==0'],
    response_failures: ['count==0'],
    dropped_iterations: ['count==0'],
  },
  systemTags: ['method', 'name', 'scenario', 'status', 'expected_response'],
  maxRedirects: 0,
};
function request(name) {
  const reply = http.get(configuration.origin + '/' + name, {
    headers: name === 'json' ? {} : { authorization: 'Bearer ' + configuration.token },
    tags: { name: '/' + name },
    redirects: 0,
    timeout: '5s',
  });
  const valid = check(reply, {
    'status is 200': (value) => value.status === 200,
    'body is the exact expected 128 bytes': (value) => value.body === configuration.expectedBody,
  });
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
