<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>
-->

# Verified LDAP and LDAPS

`@arkenivajs/security-ldap` adapts pinned `ldapts@9.2.0`. Register `ldapPlugin(settings)`, start the application, and resolve `LDAP_CAPABILITY` as `LdapService`. `createLdapService(settings)` provides the same five standalone operations without application lifecycle integration. Imports and factories perform no provider or network I/O.

`findUser({username}, options)` returns one immutable `{dn,uid,attributes}` or null; ambiguous matches fail. `getGroups(userDn, options)` returns immutable `{dn,name}` groups with bounded nested membership and cycle deduplication. `search(query, options)` yields immutable `{dn,attributes}` entries using native paging. `verifyCredentials({username}, password, options)` uses a fresh user connection and returns false only for an absent user, an empty/NUL password or the directory's invalid-credentials response to that user bind. Provider, service-bind, persistence-independent transport and TLS failures throw. `ping(options)` requires a verified authenticated service connection.

## Trusted deployment configuration

Settings require `url`, `baseDn`, `groupSearchBaseDn`, `userFilterTemplate`, `serviceBindDnRef`, `serviceBindPasswordRef` and external `secretProvider`. Optional `tlsTrustBundleRef` resolves a PEM CA bundle; otherwise native system trust applies. Secret values require bounded UTF-8 bytes, an immutable version and an unexpired optional expiry. Provider-owned buffers remain untouched; temporary owned byte copies are erased. JavaScript strings and native IPC serialization cannot provide a guarantee of physical memory erasure. Passwords never enter process arguments, environment, files, logs or telemetry.

Only `ldaps://host:port` or `ldap://host:port` with `requireStartTls:true` is permitted. URL credentials, paths, queries and fragments are rejected. TLS requires certificate and hostname verification and at least TLS 1.2. No plaintext bind, downgrade, automatic reconnect, rebind or referral following occurs. An interrupted connection requires a new public operation. The configured endpoint is a trusted application deployment decision, never a user-supplied URL.

`allowedAttributes` defaults to `uid`, `cn`, `memberOf`, `sAMAccountName` and is normalized case-insensitively. At most 32 names are allowed, including `cn` and either `uid` or `sAMAccountName`. Credential attributes, wildcard projections, binary values that are not valid UTF-8 and unrequested returned attributes are rejected. Returned attribute keys are lowercase and values are readonly string arrays. `environment` defaults to production; plugin settings must match core. Test-only marked providers are rejected outside test, including inherited markers. These two optional settings complete the normative whitelist and environment requirements without changing the five operations.

Filter templates contain named placeholders such as `(uid={username})` and `(&(objectClass=inetOrgPerson)(uid={username}))`. A placeholder occupies a complete assertion value or substring component, never an attribute or grammar position. The upstream parser reads bounded trusted structure; values are then bound into native BER filter objects. Hostile parentheses, backslashes, asterisks and Unicode stay assertion data. Unknown, unused or partial placeholders fail. Templates have at most 8192 UTF-8 bytes, depth 32 and 256 filter nodes. Search attributes must be approved; filter attributes are approved names plus `objectClass` and `member`.

A search query requires `baseDn`, `filter:{template,values}` and a nonempty `attributes` list. The base must exactly equal a configured user or group base; arbitrary DN suffix parsing is deliberately unnecessary. Group member DNs are equality assertion data, and password binds use only a DN returned by the configured directory. No request value is concatenated into DN grammar. Caller identity, tenant authorization, directory ACLs and safe exposure of search results remain application responsibilities.

## Bounds, streaming and ownership

`maxEntries` defaults to 1000, maximum 5000; `maxGroupDepth` defaults to 8, maximum 32; `timeoutMs` defaults to 5000, maximum 30000. All are positive integers. A search can tighten `maxEntries` and select `pageSize` from 1 to 256, default 100. Limits never silently produce a successful truncated list: overflow raises `EK_LDAP_SEARCH`, including unseen groups beyond the depth limit. Streamed entries received before an eventual error remain partial results, never a completion acknowledgement.

Each service admits four operations with no queue. Saturation fails immediately. Each operation owns an isolated Node process with a 64 MiB old-space budget, native LDAP clients and sockets. This isolates upstream BER parsing faults and prevents `NODE_DEBUG=ldapts`, `NODE_OPTIONS` or application environment secrets from reaching the native worker. It is process isolation, not an OS security sandbox. Each client allows one TCP connection and, for STARTTLS, one upgrade. No user connection is reused as a service connection.

Operations enforce an 8 MiB received-wire budget and bounded projections, including at most 128 values per attribute and 16 KiB per value. Native pages are bounded and private IPC admits one entry at a time with consumer acknowledgement. A search is lazy and single-pass; concurrent `next()` calls are rejected. Early return kills the owned process and waits for exit. A paused iterator's original deadline still kills its worker. Abort and deadlines do not claim to roll back remote authentication side effects; interrupted work may report `details.outcome:'unknown'`.

Uncooperative secret-provider work retains its admission slot until it really settles and cannot start a late child after cancellation. Plugin drain aborts work and waits for owned completion; a provider that never settles can produce an explicit core shutdown deadline failure. Standalone calls have the same finite deadlines but no application-wide close method. Successful results are acknowledged only after the native process has exited. Plugin calls require core READY and fail after shutdown.

Optional Pino and OTel adapters record fixed operation/outcome, native bind latency, search-page count, group depth and timeout count. No username, DN, password, endpoint or secret reference is accepted as a metric label or diagnostic field. The existing common errors and `EK_LDAP_CONNECT`, `EK_LDAP_BIND`, `EK_LDAP_FILTER`, `EK_LDAP_SEARCH` contain generic messages without native exception causes.

See [the executable consumer](../../examples/ldap/README.md). The functional matrix uses real OpenLDAP 2.6 with verified LDAPS/STARTTLS. Microsoft AD staging compatibility, comparative performance, soak and final release gates remain separate requirements; no MFA assurance or production-ready release claim follows from these tests.
