# @arkenivajs/config

Strict layered configuration for ESM applications. `createConfig<T>(options)` returns a typed `ConfigService<T>`. Supply a JSON Schema and an existing approved workspace directory. Precedence is defaults, YAML, explicitly mapped `ARKENIVAJS_*` environment variables, then the runtime object.

Unknown keys and environment mappings, duplicate YAML keys, aliases, unsafe objects and invalid numeric/boolean values reject with `EK_CONFIG_INVALID`. YAML files are confined to the approved workspace, including symlink resolution. Secret fields belong in environment mappings rather than YAML, defaults or runtime data. Snapshots redact known secret keys and `secretPaths`; trusted component getters may access resolved secrets.

`get`, `require` and `has` select declared top-level keys. `require` rejects missing or null values with `EK_CONFIG_MISSING`; `has` considers an explicitly nullable value present. Values and snapshots are deeply immutable. `reload(updates)` changes only declared `dynamicPaths`, validates the complete configuration and runs a side-effect-free preflight before one atomic swap. Rejection uses `EK_CONFIG_RELOAD_REJECTED` and retains the prior generation. Credentials and security policy require reconstruction.

`configPlugin(service)` installs an already validated configuration service through the core plugin registry. Load application options before calling `createApplication` so validation and secret resolution finish before any plugin opens resources. No global process configuration is modified.

Run the workspace `pnpm verify` command to build and exercise the unit, contract and seeded property suites. The configuration tests require no external service.

Optional `secrets` maps configuration paths to provider reference names. `secretProvider(reference, options)` resolves them before the service is returned. Explicit environment values take precedence over provider resolution, and every provider path is automatically redacted and protected from dynamic reload. Configure `signal` and `timeoutMs` to bound loading and provider work; timeout defaults to 30,000 ms. Providers should honor the supplied signal. `EK_CONFIG_MISSING` identifies an empty provider response; abort and deadline failures use `EK_ABORTED` and `EK_TIMEOUT`.

Set `preflightTimeoutMs` to bound dynamic reload validation. A timed-out preflight cannot commit later; the prior immutable generation remains active.

Validated overrides emit one `configuration.override.applied` diagnostic per contributing layer, identifying `source` and the count of overlapping top-level keys. Successful reloads emit `configuration.reload.applied` with the number of submitted top-level keys, including successful no-ops. Events contain no paths, values, provider references or native errors. Rejected changes emit no applied event. By default these small JSON events go to standard error; pass synchronous `onDiagnostic(event)` to route them into an application logger or another owned sink. A throwing sink falls back to safe standard-error output and cannot change an accepted configuration outcome.
