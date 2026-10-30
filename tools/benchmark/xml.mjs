// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import assert from 'node:assert/strict';
import { runPureComparison } from './pure-comparison.mjs';
import { xmlFixture, xmlSettings } from './xml-workload.mjs';
import { prepareXmlXsd, xmlSchemaArtifacts, xmlNativeVersion } from './xml-xsd.mjs';

const args = process.argv.slice(2);
assert.ok(
  args.length === 2 && ['--verify', '--smoke'].includes(args[0]),
  'Use --verify or bounded --smoke with a fresh absolute external report directory',
);
assert.ok(
  args[0] !== '--smoke' ||
    (process.env.ARKENIVA_XML_DISPOSABLE === '1' && process.env.ARKENIVA_XML_NS_ACTIVE === '1'),
  'XML smoke requires the existing disposable isolated-network fixture',
);
let snapshot;
try {
  if (args[0] === '--smoke') snapshot = await prepareXmlXsd();
  const fixture = { ...xmlFixture, ...(snapshot ? { xsd: snapshot.configuration } : {}) };
  await runPureComparison(
    {
      scenarioId: 'xml-native-ordered-document-interoperability',
      superviseProcessTree: true,
      fixture,
      privacyValues: Object.values(xmlFixture),
      privacyField: 'inputOccurrences',
      worker: new URL('./xml-worker.mjs', import.meta.url),
      inputs: {
        nativeBackend: 'fast-xml-parser@5.11.2 and saxes@6.0.0',
        operations: ['parse', 'stringify'],
        documentsPerProfile: 3,
        namespaceMode: 'preserve',
        concurrency: 1,
        samplingSupported: true,
        resourceLimits: xmlSettings,
        ...(snapshot
          ? {
              nativeXsdVersion: xmlNativeVersion,
              xsdSchemaArtifacts: xmlSchemaArtifacts,
              namespaceIsolation:
                'Inherited non-root OS network namespace, only loopback; inode checked per worker without forwarding markers',
              measuredOperation: 'validate-xsd-invoice',
              parseWriterTiming:
                'Functional startup verification only; no parse/write performance claim',
              measuredIterations: 100,
              excludedWarmupIterations: 20,
              retainedValidationReportByteLimit: 65536,
            }
          : {}),
      },
      observationCoverage:
        'Actual native/public ordered XML tree and writer interoperability in four isolated profiles: mixed content, string attributes, namespace prefixes, Unicode/entities, CDATA and comments. Smoke additionally executes real native offline XSD decisions and independent output checks. Real SDK exports exclude documents and namespaces.',
      limitations:
        'Small valid self-contained corpus with native SAX syntax/namespace validation and explicit DTD rejection. Native baseline omits framework hostile-object capture, complete security limits, bounded Worker-thread isolation, cancellation, expanded-name policy and lifecycle checks. Smoke times one closed-loop XSD validation with bounded report capture/assertion costs; parser/writer behavior is verified before timing only; warmup latency samples are excluded. Whole supervised lifecycle includes startup, verification, warmup, measured operations, independent completion fixed-document parse/XSD and validation-report checks, export and cleanup; Node Worker threads share process accounting. Python observer, parent/collector and external servers are excluded. Diagnostic samplingRatio=1 in standard/detailed is not a normal production budget. No parser/writer timing, calibrated observer overhead, matched open-loop load, confidence interval, performance budget, five repetitions, one-hour soak or release acceptance claim.',
    },
    args,
  );
} finally {
  await snapshot?.close();
}
