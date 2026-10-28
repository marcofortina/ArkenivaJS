// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';
import type { Browser, BrowserContext } from 'playwright-core';
import { base, fixture } from '../fixture.js';

const endpoint = process.env.ARKENIVA_GRAPHQL_BROWSER_URL;
const origin = process.env.ARKENIVA_GRAPHQL_BROWSER_ORIGIN;
if (process.env.ARKENIVA_GRAPHQL_BROWSER_DISPOSABLE !== '1' || !endpoint || !origin)
  throw new Error('GraphQL browser acceptance requires an explicitly disposable loopback browser');
for (const value of [endpoint, origin]) {
  const url = new URL(value);
  if (
    url.protocol !== 'http:' ||
    !['127.0.0.1', 'localhost'].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/'
  )
    throw new Error('The disposable browser and application must use explicit loopback origins');
}

test(
  'GraphQL IDE renders local workers, executes through authenticated HTTP and persists no browser data',
  { timeout: 60000 },
  async () => {
    const browserOrigin = new URL(origin);
    const f = await fixture(
      {
        ...base(),
        security: {
          authorizeField: () => true,
          developerIDE: true,
          introspection: 'authenticated',
          introspectionScope: 'graphql:admin',
          limits: { maxComplexity: 100000000, maxDepth: 50, maxFieldExecutions: 100000 },
        },
      },
      { port: Number(browserOrigin.port) },
    );
    let browser: Browser | undefined, context: BrowserContext | undefined;
    try {
      browser = await chromium.connectOverCDP(endpoint, { timeout: 10000 });
      context = await browser.newContext({
        extraHTTPHeaders: { authorization: await f.token('tenant-a', 'graphql:admin') },
      });
      const page = await context.newPage();
      const errors: string[] = [],
        requested = new Set<string>();
      page.on('pageerror', (error) => errors.push(error.message));
      const worker = page.waitForEvent('worker', {
        predicate: (worker) => worker.url().includes('worker-graphql.js'),
        timeout: 15000,
      });
      void worker.catch(() => undefined);
      context.on('request', (request) => requested.add(request.url()));
      const response = await page.goto(new URL('/graphql/ide', browserOrigin).href);
      assert.equal(response?.status(), 200);
      await page
        .getByRole('button', { name: /execute query/i })
        .waitFor({ state: 'visible', timeout: 30000 });
      await page.locator('.monaco-editor').first().waitFor({ state: 'visible' });
      const result = page.waitForResponse((response) => {
        if (
          new URL(response.url()).pathname !== '/graphql' ||
          response.request().method() !== 'POST'
        )
          return false;
        const body = response.request().postDataJSON() as { query?: string };
        return !!body.query?.includes('__typename') && !body.query.includes('__schema');
      });
      await page.getByRole('button', { name: /execute query/i }).click();
      assert.deepEqual(await (await result).json(), { data: { __typename: 'Query' } });
      await page.locator('.monaco-editor').first().click();
      await page.keyboard.press('Control+Space');
      const languageWorker = await worker;
      assert.equal(new URL(languageWorker.url()).origin, browserOrigin.origin);
      assert.equal(await languageWorker.evaluate(() => typeof globalThis.onmessage), 'function');
      await page.keyboard.press('Escape');
      assert.equal(await page.evaluate(() => localStorage.length), 0);
      assert.equal(await page.evaluate(() => sessionStorage.length), 0);
      for (const value of requested)
        assert.equal(
          new URL(value).origin,
          browserOrigin.origin,
          'The IDE must not request a CDN or external origin',
        );
      assert.deepEqual(errors, []);
      assert.doesNotMatch(f.logs(), /Bearer |authorization|query \{/);
    } finally {
      try {
        await context?.close();
      } finally {
        try {
          await browser?.close();
        } finally {
          await f.close();
        }
      }
    }
  },
);
