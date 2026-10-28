// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import { nativeWsdl } from './backend.js';
import { failure } from './validation.js';

const source = `<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:s="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:x="http://www.w3.org/2001/XMLSchema" xmlns:t="urn:arkenivajs:soap:probe" targetNamespace="urn:arkenivajs:soap:probe">
<types><x:schema targetNamespace="urn:arkenivajs:soap:probe" elementFormDefault="qualified"><x:element name="Probe"><x:complexType><x:sequence><x:element name="value" type="x:string"/></x:sequence></x:complexType></x:element><x:element name="ProbeResponse"><x:complexType><x:sequence><x:element name="value" type="x:int"/><x:element name="text" type="x:string"/></x:sequence></x:complexType></x:element></x:schema></types>
<message name="ProbeInput"><part name="parameters" element="t:Probe"/></message><message name="ProbeOutput"><part name="parameters" element="t:ProbeResponse"/></message><portType name="ProbePortType"><operation name="Probe"><input message="t:ProbeInput"/><output message="t:ProbeOutput"/></operation></portType>
<binding name="ProbeBinding" type="t:ProbePortType"><s:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/><operation name="Probe"><s:operation soapAction="urn:arkenivajs:soap:probe:Probe"/><input><s:body use="literal"/></input><output><s:body use="literal"/></output></operation></binding><service name="ProbeService"><port name="ProbePort" binding="t:ProbeBinding"><s:address location="https://probe.fixture.invalid/soap"/></port></service></definitions>`;

/** Fail startup when an independently installed native dependency lacks the reviewed fidelity fix. */
export async function verifyBackend(): Promise<void> {
  try {
    const native = await nativeWsdl(source, true);
    const result = native.xmlToObject(
      '<e:Envelope xmlns:e="http://schemas.xmlsoap.org/soap/envelope/"><e:Body><ProbeResponse xmlns="urn:arkenivajs:soap:probe"><value>1<![CDATA[2]]></value><text>  bounded  </text></ProbeResponse></e:Body></e:Envelope>',
    ) as { Body?: { ProbeResponse?: { value?: unknown; text?: unknown } } };
    if (
      result.Body?.ProbeResponse?.value !== 12 ||
      result.Body.ProbeResponse.text !== '  bounded  '
    )
      throw failure();
  } catch {
    throw failure('EK_BACKEND_UNAVAILABLE');
  }
}
