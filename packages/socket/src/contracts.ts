// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

import type { OperationOptions, ServerTlsFiles } from '@arkenivajs/core';

/** Native server transports; stream bytes never imply application framing. */
export type SocketServerKind = 'tcp' | 'tls' | 'udp' | 'unix';
export type SocketServerState = 'CREATED' | 'LISTENING' | 'DRAINING' | 'FAILED' | 'CLOSED';
export type UdpAddressFamily = 'udp4' | 'udp6';
export interface SocketCommonLimits {
  readonly shutdownTimeoutMs?: number;
}
export interface StreamLimits extends SocketCommonLimits {
  readonly maxConnections?: number;
  readonly idleTimeoutMs?: number;
  readonly maxPendingWriteBytes?: number;
}
export interface TcpSocketOptions extends StreamLimits {
  readonly name: string;
  readonly host?: string;
  readonly port: number;
  readonly ipv6Only?: boolean;
}
export interface TlsSocketOptions extends TcpSocketOptions {
  readonly tls: ServerTlsFiles;
  readonly handshakeTimeoutMs?: number;
}
export interface UnixSocketOptions extends StreamLimits {
  readonly name: string;
  readonly path: string;
  readonly mode?: number;
}
export interface UdpSocketOptions extends SocketCommonLimits {
  readonly name: string;
  readonly family: UdpAddressFamily;
  readonly host?: string;
  readonly port: number;
  readonly ipv6Only?: boolean;
  readonly maxDatagramBytes?: number;
  readonly maxConcurrentHandlers?: number;
  readonly maxQueuedDatagrams?: number;
  readonly maxReplyBytes?: number;
  readonly maxReplyAmplificationFactor?: number;
  readonly allowOutboundDestinations?: boolean;
  readonly destinationAllowlist?: readonly string[];
}
/** Network coordinates provide routing metadata, never identity or tenant authority. */
export interface SocketNetworkAddress {
  readonly address: string;
  readonly port: number;
  readonly family: 'IPv4' | 'IPv6';
}
export interface SocketServerBinding {
  readonly kind: SocketServerKind;
  readonly network?: SocketNetworkAddress;
  readonly path?: string;
}
export interface SocketStats {
  readonly state: SocketServerState;
  readonly acceptedConnections: number;
  readonly activeConnections: number;
  readonly rejectedConnections: number;
  readonly receivedApplicationBytes: number;
  readonly sentApplicationBytes: number;
  readonly droppedDatagrams: number;
  readonly errors: number;
  readonly observedAt: string;
}
export interface SocketServerHandle {
  readonly name: string;
  readonly kind: SocketServerKind;
  readonly state: SocketServerState;
  readonly boundAddress: SocketServerBinding | undefined;
  start(options?: OperationOptions): Promise<SocketServerBinding>;
  stop(options?: OperationOptions): Promise<void>;
  stats(): SocketStats;
}
export interface SocketPeer {
  readonly connectionId: string;
  readonly remote: SocketNetworkAddress | undefined;
  readonly signal: AbortSignal;
  /** One consumer only; arbitrary byte chunks are not protocol messages. */
  chunks(): AsyncIterable<Uint8Array>;
  /** Writable acceptance is not proof of remote receipt. */
  send(data: Uint8Array, options?: OperationOptions): Promise<void>;
  end(options?: OperationOptions): Promise<void>;
  close(): void;
}
export type SocketPeerHandler = (peer: SocketPeer) => Promise<void> | void;
export interface UdpDatagram {
  readonly bytes: Uint8Array;
  readonly remote: SocketNetworkAddress;
  readonly receivedAt: string;
}
export interface UdpSocketHandle extends SocketServerHandle {
  reply(input: UdpDatagram, data: Uint8Array, options?: OperationOptions): Promise<void>;
  sendTo(target: SocketNetworkAddress, data: Uint8Array, options?: OperationOptions): Promise<void>;
}
export type UdpDatagramHandler = (
  datagram: UdpDatagram,
  server: UdpSocketHandle,
) => Promise<void> | void;
export type SocketListenerDefinition =
  | {
      readonly kind: 'tcp';
      readonly options: TcpSocketOptions;
      readonly handler: SocketPeerHandler;
    }
  | {
      readonly kind: 'tls';
      readonly options: TlsSocketOptions;
      readonly handler: SocketPeerHandler;
    }
  | {
      readonly kind: 'unix';
      readonly options: UnixSocketOptions;
      readonly handler: SocketPeerHandler;
    }
  | {
      readonly kind: 'udp';
      readonly options: UdpSocketOptions;
      readonly handler: UdpDatagramHandler;
    };
export interface SocketPluginOptions {
  readonly listeners?: readonly SocketListenerDefinition[];
}
export interface SocketListenerInfo {
  readonly name: string;
  readonly kind: SocketServerKind;
  readonly state: SocketServerState;
  readonly binding?: SocketServerBinding;
}
export interface SocketService {
  createTcpServer(options: TcpSocketOptions, handler: SocketPeerHandler): SocketServerHandle;
  createTlsServer(options: TlsSocketOptions, handler: SocketPeerHandler): SocketServerHandle;
  createUnixServer(options: UnixSocketOptions, handler: SocketPeerHandler): SocketServerHandle;
  createUdpServer(options: UdpSocketOptions, handler: UdpDatagramHandler): UdpSocketHandle;
  list(): readonly SocketListenerInfo[];
}
