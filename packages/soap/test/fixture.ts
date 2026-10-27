// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

/** A complete independently authored document/literal contract for native conformance. */
export const contract = `<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
 xmlns:tns="urn:arkenivajs:stock" xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:arkenivajs:stock">
 <types><xs:schema targetNamespace="urn:arkenivajs:stock" elementFormDefault="qualified">
  <xs:element name="ReadStock"><xs:complexType><xs:sequence><xs:element name="sku" type="xs:string"/></xs:sequence></xs:complexType></xs:element>
  <xs:element name="ReadStockResponse"><xs:complexType><xs:sequence><xs:element name="quantity" type="xs:int"/></xs:sequence></xs:complexType></xs:element>
 </xs:schema></types>
 <message name="ReadStockInput"><part name="parameters" element="tns:ReadStock"/></message>
 <message name="ReadStockOutput"><part name="parameters" element="tns:ReadStockResponse"/></message>
 <portType name="InventoryPortType"><operation name="ReadStock"><input message="tns:ReadStockInput"/><output message="tns:ReadStockOutput"/></operation></portType>
 <binding name="InventoryBinding" type="tns:InventoryPortType"><soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
  <operation name="ReadStock"><soap:operation soapAction="urn:arkenivajs:ReadStock"/><input><soap:body use="literal"/></input><output><soap:body use="literal"/></output></operation>
 </binding>
 <service name="InventoryService"><port name="InventoryPort" binding="tns:InventoryBinding"><soap:address location="https://inventory.fixture.invalid/soap"/></port></service>
</definitions>`;
export const response = `<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><ReadStockResponse xmlns="urn:arkenivajs:stock"><quantity>12</quantity></ReadStockResponse></s:Body></s:Envelope>`;
