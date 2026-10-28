// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { GraphiQL } from 'graphiql';
import type { GraphiQLProps } from 'graphiql';
import 'graphiql/style.css';

const environment = globalThis as typeof globalThis & {
  MonacoEnvironment: { getWorker(id: string, label: string): Worker };
};
environment.MonacoEnvironment = {
  getWorker(_id, label) {
    const name =
      label === 'json'
        ? 'worker-json.js'
        : label === 'graphql'
          ? 'worker-graphql.js'
          : 'worker-editor.js';
    return new Worker(new URL(name, import.meta.url), { type: 'module' });
  },
};
const node = document.querySelector<HTMLMetaElement>('meta[name="arkenivajs-graphql-endpoint"]');
const mount = document.getElementById('graphql-ide');
if (!node || !mount) throw new Error('The GraphQL IDE configuration is unavailable');
const endpoint = new URL(node.content, location.origin);
if (endpoint.origin !== location.origin)
  throw new Error('The GraphQL IDE endpoint must use the same origin');
const fetcher: GraphiQLProps['fetcher'] = async (parameters, options) => {
  const response = await fetch(endpoint, {
    method: 'POST',
    credentials: 'omit',
    headers: { ...options?.headers, 'content-type': 'application/json' },
    body: JSON.stringify(parameters),
  });
  if (response.status === 204) throw new Error('The GraphQL response is unavailable');
  return response.json();
};
createRoot(mount).render(
  createElement(GraphiQL, {
    fetcher,
    storage: Object.freeze({
      length: 0,
      getItem: () => null,
      setItem() {},
      removeItem() {},
      clear() {},
    }),
    shouldPersistHeaders: false,
    showPersistHeadersSettings: false,
    defaultEditorToolsVisibility: 'headers',
    defaultQuery: 'query { __typename }',
  }),
);
