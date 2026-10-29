// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { parentPort, workerData } from 'node:worker_threads';
import { inflateRawSync } from 'node:zlib';
import { TextDecoder } from 'node:util';
import { SAML, ValidateInResponseTo } from '@node-saml/node-saml';
import type { CacheProvider, SamlConfig } from '@node-saml/node-saml';
import { signSamlPost, signAuthnRequestPost } from '@node-saml/node-saml/lib/saml-post-signing.js';
import { XMLSerializer } from '@xmldom/xmldom';
import { KitError } from '@arkenivajs/core';
import type { NativeRequest, NativeResult, VerifiedAssertion } from './backend-contracts.js';
import { parse, NS, children, one, content, strongSignatures } from './xml.js';
import { failure, text } from './validation.js';

function base64(input: string): string {
  if (typeof input !== 'string' || input.length > 349528 || !/^[A-Za-z0-9+/]+={0,2}$/.test(input))
    throw failure('EK_SAML_ASSERTION');
  const bytes = Buffer.from(input, 'base64');
  if (bytes.toString('base64') !== input || bytes.length > 262144)
    throw failure('EK_SAML_ASSERTION');
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
function timestamp(value: string | null, required = true): number | undefined {
  if ((value === null || value === '') && !required) return undefined;
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value) ||
    !Number.isFinite(Date.parse(value))
  )
    throw failure('EK_SAML_ASSERTION');
  const normalized = value.includes('.')
    ? value.replace(
        /\.(\d{1,3})Z$/,
        (_match, fraction: string) => '.' + fraction.padEnd(3, '0') + 'Z',
      )
    : value.replace('Z', '.000Z');
  if (new Date(value).toISOString() !== normalized) throw failure('EK_SAML_ASSERTION');
  return Date.parse(value);
}
function id(value: string | null): string {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,255}$/.test(value))
    throw failure('EK_SAML_ASSERTION');
  return value;
}
function message(
  input: NativeRequest,
  xml: string,
  kind: 'Response' | 'LogoutResponse',
  signed: boolean,
): Element {
  const root = parse(xml).documentElement,
    config = input.configuration,
    now = Date.now(),
    skew = config.clockSkewSeconds * 1000;
  if (
    root.namespaceURI !== NS.protocol ||
    root.localName !== kind ||
    root.getAttribute('Version') !== '2.0' ||
    root.getAttribute('InResponseTo') !== input.requestId ||
    root.getAttribute('Destination') !== config.acsUrl ||
    content(one(root, NS.assertion, 'Issuer'), 2048) !== config.issuer
  )
    throw failure('EK_SAML_ASSERTION');
  id(root.getAttribute('ID'));
  const issued = timestamp(root.getAttribute('IssueInstant'))!;
  if (issued > now + skew || issued + 300000 + skew <= now) throw failure('EK_SAML_ASSERTION');
  if (
    one(one(root, NS.protocol, 'Status'), NS.protocol, 'StatusCode').getAttribute('Value') !==
    'urn:oasis:names:tc:SAML:2.0:status:Success'
  )
    throw failure('EK_SAML_ASSERTION');
  if (signed) strongSignatures(root);
  return root;
}
function assertion(
  input: NativeRequest,
  verifiedXml: string,
  responseId: string,
  responseExpiresAt: number,
  responseIssuerFormat?: string,
): VerifiedAssertion {
  const root = parse(verifiedXml).documentElement,
    config = input.configuration,
    now = Date.now(),
    skew = config.clockSkewSeconds * 1000;
  if (
    root.namespaceURI !== NS.assertion ||
    root.localName !== 'Assertion' ||
    root.getAttribute('Version') !== '2.0' ||
    content(one(root, NS.assertion, 'Issuer'), 2048) !== config.issuer
  )
    throw failure('EK_SAML_ASSERTION');
  const issued = timestamp(root.getAttribute('IssueInstant'))!;
  if (issued > now + skew || issued + 300000 + skew <= now) throw failure('EK_SAML_ASSERTION');
  const subject = one(root, NS.assertion, 'Subject'),
    name = one(subject, NS.assertion, 'NameID');
  const confirmation = one(subject, NS.assertion, 'SubjectConfirmation'),
    data = one(confirmation, NS.assertion, 'SubjectConfirmationData');
  if (
    confirmation.getAttribute('Method') !== 'urn:oasis:names:tc:SAML:2.0:cm:bearer' ||
    data.getAttribute('InResponseTo') !== input.requestId ||
    data.getAttribute('Recipient') !== config.acsUrl
  )
    throw failure('EK_SAML_ASSERTION');
  const confirmationExpires = timestamp(data.getAttribute('NotOnOrAfter'))!;
  if (confirmationExpires + skew <= now) throw failure('EK_SAML_ASSERTION');
  const confirmationBefore = timestamp(data.getAttribute('NotBefore'), false);
  if (confirmationBefore !== undefined && confirmationBefore - skew > now)
    throw failure('EK_SAML_ASSERTION');
  const conditions = one(root, NS.assertion, 'Conditions'),
    expires = timestamp(conditions.getAttribute('NotOnOrAfter'))!,
    before = timestamp(conditions.getAttribute('NotBefore'), false);
  if (expires + skew <= now || (before !== undefined && before - skew > now))
    throw failure('EK_SAML_ASSERTION');
  const restrictions = children(conditions, NS.assertion, 'AudienceRestriction');
  if (
    !restrictions.length ||
    restrictions.length > 4 ||
    restrictions.some(
      (restriction) =>
        !children(restriction, NS.assertion, 'Audience').some(
          (audience) => content(audience, 2048) === config.audience,
        ),
    )
  )
    throw failure('EK_SAML_ASSERTION');
  const statement = one(root, NS.assertion, 'AuthnStatement'),
    authenticated = timestamp(statement.getAttribute('AuthnInstant'))!,
    sessionExpires =
      timestamp(statement.getAttribute('SessionNotOnOrAfter'), false) ?? now + 28800000;
  if (authenticated > now + skew || sessionExpires + skew <= now)
    throw failure('EK_SAML_ASSERTION');
  const authentication = one(statement, NS.assertion, 'AuthnContext'),
    classRefs = children(authentication, NS.assertion, 'AuthnContextClassRef');
  if (classRefs.length > 1) throw failure('EK_SAML_ASSERTION');
  if (
    config.requestedAuthnContext &&
    (classRefs.length !== 1 ||
      !config.requestedAuthnContext.acceptedClassReferences.includes(content(classRefs[0]!, 2048)))
  )
    throw failure('EK_SAML_ASSERTION');
  const attributes: Record<string, readonly string[]> = Object.create(null);
  let entries = 0,
    bytes = 0;
  for (const statement of children(root, NS.assertion, 'AttributeStatement'))
    for (const attribute of children(statement, NS.assertion, 'Attribute')) {
      if (++entries > 128) throw failure('EK_SAML_ASSERTION');
      const name = text(attribute.getAttribute('Name'), 256);
      if (
        ['__proto__', 'constructor', 'prototype'].includes(name) ||
        Object.hasOwn(attributes, name)
      )
        throw failure('EK_SAML_ASSERTION');
      const values = children(attribute, NS.assertion, 'AttributeValue').map((value) =>
        content(value, 8192),
      );
      if (!values.length || values.length > 32) throw failure('EK_SAML_ASSERTION');
      bytes +=
        Buffer.byteLength(name) +
        values.reduce((total, value) => total + Buffer.byteLength(value), 0);
      if (bytes > 32768) throw failure('EK_SAML_ASSERTION');
      attributes[name] = Object.freeze(values);
    }
  const verificationExpiresAt = Math.min(
    responseExpiresAt,
    issued + 300000 + skew,
    confirmationExpires + skew,
    expires + skew,
    sessionExpires + skew,
    Date.parse(input.instant) + 300000,
  );
  if (verificationExpiresAt <= Date.now()) throw failure('EK_SAML_ASSERTION');
  return {
    issuer: config.issuer,
    subject: content(name, 1024),
    responseId,
    assertionId: id(root.getAttribute('ID')),
    attributes,
    ...(classRefs.length ? { authnContext: content(classRefs[0]!, 2048) } : {}),
    nameIDFormat:
      name.getAttribute('Format') || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    ...(name.hasAttribute('NameQualifier')
      ? { nameQualifier: text(name.getAttribute('NameQualifier'), 2048) }
      : {}),
    ...(name.hasAttribute('SPNameQualifier')
      ? { spNameQualifier: text(name.getAttribute('SPNameQualifier'), 2048) }
      : {}),
    ...(statement.hasAttribute('SessionIndex')
      ? { sessionIndex: text(statement.getAttribute('SessionIndex'), 256) }
      : {}),
    sessionExpiresAt: new Date(Math.min(sessionExpires, now + 28800000)).toISOString(),
    verificationExpiresAt: new Date(verificationExpiresAt).toISOString(),
    profile: {
      ...(one(root, NS.assertion, 'Issuer').hasAttribute('Format')
        ? {
            assertionIssuerFormat: text(
              one(root, NS.assertion, 'Issuer').getAttribute('Format'),
              2048,
              true,
            ),
          }
        : {}),
      ...(responseIssuerFormat === undefined ? {} : { responseIssuerFormat }),
      conditionsNotBeforePresent: before !== undefined,
      advicePresent: children(root, NS.assertion, 'Advice').length !== 0,
    },
  };
}
async function run(input: NativeRequest): Promise<NativeResult> {
  const selected = input.configuration;
  let saved: string | null = input.instant;
  const cache: CacheProvider = {
    async saveAsync(key, value) {
      if (key !== input.requestId || !Number.isFinite(Date.parse(value)))
        throw failure('EK_SAML_ASSERTION');
      saved = value;
      return { value, createdAt: Date.parse(value) };
    },
    async getAsync(key) {
      return key === input.requestId ? saved : null;
    },
    async removeAsync(key) {
      if (key !== input.requestId) return null;
      const result = saved;
      saved = null;
      return result;
    },
  };
  const options: SamlConfig = {
    issuer: selected.entityId,
    callbackUrl: selected.acsUrl,
    entryPoint: selected.loginUrl,
    audience: selected.audience,
    idpIssuer: selected.issuer,
    idpCert: [...selected.certificates],
    acceptedClockSkewMs: selected.clockSkewSeconds * 1000,
    maxAssertionAgeMs: 300000,
    requestIdExpirationPeriodMs: 300000,
    validateInResponseTo:
      input.action === 'verify-logout' && selected.binding === 'post'
        ? ValidateInResponseTo.never
        : ValidateInResponseTo.always,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    signMetadata: selected.privateKey !== undefined,
    signatureAlgorithm: 'sha256',
    digestAlgorithm: 'sha256',
    authnRequestBinding: selected.binding === 'post' ? 'HTTP-POST' : 'HTTP-Redirect',
    skipRequestCompression: selected.binding === 'post',
    generateUniqueId: () => input.requestId,
    cacheProvider: cache,
    ...(selected.requestedAuthnContext
      ? {
          authnContext: [...selected.requestedAuthnContext.classReferences],
          racComparison: selected.requestedAuthnContext.comparison,
        }
      : {}),
    ...(selected.authenticationRequestProfile
      ? {
          forceAuthn:
            selected.requestedAuthnContext!.classReferences[0] !== 'https://www.spid.gov.it/SpidL1',
          identifierFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
          allowCreate: false,
          ...(selected.authenticationRequestProfile.attributeConsumingServiceIndex === undefined
            ? {}
            : {
                attributeConsumingServiceIndex: String(
                  selected.authenticationRequestProfile.attributeConsumingServiceIndex,
                ),
              }),
        }
      : {}),
    logoutCallbackUrl: selected.acsUrl,
    ...(selected.logoutUrl ? { logoutUrl: selected.logoutUrl } : {}),
    ...(selected.privateKey
      ? { privateKey: selected.privateKey, publicCert: selected.publicCert! }
      : {}),
  };
  /** Apply prescribed request attributes before delegating signing to the unchanged pinned SDK. */
  class ProfiledRequestSaml extends SAML {
    protected override async generateAuthorizeRequestAsync(
      isPassive: boolean,
      isHttpPostBinding: boolean,
    ): Promise<string> {
      if (isPassive || !selected.privateKey || !selected.publicCert)
        throw failure('EK_SAML_ASSERTION');
      const document = parse(await super.generateAuthorizeRequestAsync(false, false)),
        root = document.documentElement;
      if (
        root.namespaceURI !== NS.protocol ||
        root.localName !== 'AuthnRequest' ||
        root.getAttribute('ID') !== input.requestId ||
        children(root, NS.signature, 'Signature').length
      )
        throw failure('EK_SAML_ASSERTION');
      const issuer = one(root, NS.assertion, 'Issuer');
      if (content(issuer, 2048) !== selected.entityId) throw failure('EK_SAML_ASSERTION');
      issuer.setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity');
      issuer.setAttribute('NameQualifier', selected.entityId);
      one(root, NS.protocol, 'NameIDPolicy').removeAttribute('AllowCreate');
      const xml = new XMLSerializer().serializeToString(document);
      return isHttpPostBinding
        ? signAuthnRequestPost(xml, {
            ...options,
            privateKey: selected.privateKey,
            publicCert: selected.publicCert,
          })
        : xml;
    }
  }
  const saml = selected.authenticationRequestProfile
    ? new ProfiledRequestSaml(options)
    : new SAML(options);
  if (input.action === 'metadata')
    return {
      kind: 'metadata',
      xml: saml.generateServiceProviderMetadata(null, selected.publicCert ?? null),
    };
  if (input.action === 'login') {
    if (selected.binding === 'redirect') {
      const url = await saml.getAuthorizeUrlAsync(input.relayState, undefined, {});
      return { kind: 'redirect', url, createdAt: saved! };
    }
    const fields = await saml.getAuthorizeMessageAsync(input.relayState, undefined, {});
    if (typeof fields.SAMLRequest !== 'string' || typeof fields.RelayState !== 'string')
      throw failure('EK_SAML_ASSERTION');
    return {
      kind: 'post',
      fields: { SAMLRequest: fields.SAMLRequest, RelayState: fields.RelayState },
      createdAt: saved!,
    };
  }
  if (input.action === 'logout') {
    if (!input.profile || !selected.logoutUrl) throw failure('EK_SAML_ASSERTION');
    const profile = { issuer: selected.issuer, ...input.profile };
    if (selected.binding === 'redirect') {
      const url = await saml.getLogoutUrlAsync(profile, input.relayState, {});
      return { kind: 'redirect', url, createdAt: saved! };
    }
    let xml = await saml._generateLogoutRequest(profile);
    if (selected.privateKey)
      xml = signSamlPost(
        xml,
        '/*[local-name(.)="LogoutRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]',
        {
          privateKey: selected.privateKey,
          publicCert: selected.publicCert!,
          signatureAlgorithm: 'sha256',
          digestAlgorithm: 'sha256',
        },
      );
    return {
      kind: 'post',
      fields: { SAMLRequest: Buffer.from(xml).toString('base64'), RelayState: input.relayState },
      createdAt: saved!,
    };
  }
  if (!input.response) throw failure('EK_SAML_ASSERTION');
  if (input.action === 'verify-login') {
    const xml = base64(input.response),
      root = message(input, xml, 'Response', true),
      responseExpiresAt =
        timestamp(root.getAttribute('IssueInstant'))! + 300000 + selected.clockSkewSeconds * 1000,
      responseIssuer = one(root, NS.assertion, 'Issuer'),
      responseIssuerFormat = responseIssuer.hasAttribute('Format')
        ? text(responseIssuer.getAttribute('Format'), 2048, true)
        : undefined;
    if (
      children(root, NS.assertion, 'Assertion').length !== 1 ||
      children(root, NS.assertion, 'EncryptedAssertion').length
    )
      throw failure('EK_SAML_ASSERTION');
    // Structural rejection grants no identity; only the native verified assertion is returned below.
    assertion(
      input,
      one(root, NS.assertion, 'Assertion').toString(),
      id(root.getAttribute('ID')),
      responseExpiresAt,
      responseIssuerFormat,
    );
    const result = await saml
      .validatePostResponseAsync({ SAMLResponse: input.response })
      .catch(() => {
        throw failure('EK_SAML_SIGNATURE');
      });
    if (result.loggedOut || !result.profile?.getAssertionXml) throw failure('EK_SAML_ASSERTION');
    return {
      kind: 'identity',
      identity: assertion(
        input,
        result.profile.getAssertionXml(),
        id(root.getAttribute('ID')),
        responseExpiresAt,
        responseIssuerFormat,
      ),
    };
  }
  if (selected.binding === 'post') {
    const xml = base64(input.response),
      root = message(input, xml, 'LogoutResponse', true);
    const result = await saml
      .validatePostResponseAsync({ SAMLResponse: input.response })
      .catch(() => {
        throw failure('EK_SAML_SIGNATURE');
      });
    if (!result.loggedOut || result.profile !== null) throw failure('EK_SAML_ASSERTION');
    return { kind: 'logout', responseId: id(root.getAttribute('ID')) };
  }
  const query = input.response.startsWith('?') ? input.response.slice(1) : input.response,
    values = new URLSearchParams(query);
  const container: Record<string, string> = Object.create(null);
  for (const [key, value] of values) {
    if (
      !['SAMLResponse', 'RelayState', 'SigAlg', 'Signature'].includes(key) ||
      Object.hasOwn(container, key)
    )
      throw failure('EK_SAML_ASSERTION');
    container[key] = value;
  }
  if (
    container.RelayState !== input.relayState ||
    container.SigAlg !== 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' ||
    !container.Signature ||
    !container.SAMLResponse
  )
    throw failure('EK_SAML_SIGNATURE');
  const compressed = Buffer.from(container.SAMLResponse, 'base64');
  if (compressed.toString('base64') !== container.SAMLResponse || compressed.length > 262144)
    throw failure('EK_SAML_ASSERTION');
  const xml = new TextDecoder('utf-8', { fatal: true }).decode(
    inflateRawSync(compressed, { maxOutputLength: 262144 }),
  );
  const root = message(input, xml, 'LogoutResponse', false),
    result = await saml.validateRedirectAsync(container, query).catch(() => {
      throw failure('EK_SAML_SIGNATURE');
    });
  if (!result.loggedOut || result.profile !== null) throw failure('EK_SAML_ASSERTION');
  return { kind: 'logout', responseId: id(root.getAttribute('ID')) };
}
void run(workerData as NativeRequest).then(
  (result) => {
    parentPort!.postMessage({ ok: true, result });
    parentPort!.close();
  },
  (error: unknown) => {
    parentPort!.postMessage({
      ok: false,
      code: error instanceof KitError ? error.code : 'EK_SAML_ASSERTION',
    });
    parentPort!.close();
  },
);
