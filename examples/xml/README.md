<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# XML and optional native XSD example

The executable TypeScript application parses and writes ordered Unicode XML,
preserves expanded namespace names and validates an invoice through a real
libxml2 engine. Its schemas contain a registered local include. The XML-only
application needs no external validator or credentials:

```sh
pnpm install --frozen-lockfile
pnpm --filter '@arkenivajs/example-xml...' build
pnpm --filter @arkenivajs/example-xml start
pnpm --filter @arkenivajs/example-xml test
pnpm test:packed:examples --example xml
```

The first command uses the exact tool versions in the root manifest. Expected
CLI output contains `roundtripEqual: true` and a positive output-byte count.
Ordinary tests also verify actual SDK observations in standard and detailed
modes, without logging document contents. `.env.example` is only an inventory;
this example loads no dotenv file and requires no secret values.

## Real XSD verification inside the integration VM

Use the owned QEMU VM or a disposable Ubuntu 24.04 CI runner for the following
system package setup. Keep the laptop unchanged. The reviewed backend pins both
vendor packages; a different/missing engine produces an explicit unsupported
capability rather than fabricated validation:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends libxml2=2.9.14+dfsg-1.3ubuntu3.10 libxml2-utils=2.9.14+dfsg-1.3ubuntu3.10
```

The fixture helper requires a non-root caller with noninteractive `sudo`, Python
3, `unshare` and `ip`. It creates a disposable network namespace, enables only
loopback, drops root identity and supplementary groups, then executes the tests.
It does not change host networking or install packages. Native tests explicitly
fail when the required environment/backend is absent; no cases are skipped.

```sh
export ARKENIVA_XML_DISPOSABLE=1
python3 examples/xml/test/fixtures/run.py -- pnpm --filter @arkenivajs/data-xml test:integration
python3 examples/xml/test/fixtures/run.py -- pnpm --filter @arkenivajs/example-xml test:integration
pnpm test:packed:examples --integration xml
```

The packed verifier installs actual framework archives outside the checkout,
strictly recompiles this source against public declarations and uses the same
namespace fixture for native execution. Package installation stays outside the
isolated test namespace. XSD tests require real valid/invalid decisions, local
schema includes and private standard/detailed SDK exports. Native package tests
add malicious imports, cycles, XXE, storage failure and actual process
termination. The namespace disappears when its command exits; each application
removes only its own private schema snapshots after native processes close.

For a reviewed deployment, the standalone XSD example is also executable:

```sh
pnpm --filter @arkenivajs/example-xml start:xsd
```

Expected output is `{"valid":true,"invalid":false}`. Application configuration
supplies trusted offline schema IDs/paths; requests never select filesystem
locations or external URLs. Unknown IDs, instance schema-location hints and
DTD/entity attacks fail explicitly. XSD 1.0 validity is provided by libxml2;
XML well-formedness and the JavaScript parser are separate checks. See the
[adapter reference](../../packages/data-xml/README.md) for resource limits,
unavailable-backend handling and immutable snapshot semantics.
