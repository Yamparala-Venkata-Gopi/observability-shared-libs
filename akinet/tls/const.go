package tls

import "github.com/akitasoftware/akita-libs/akinet"

const (
	// Minimum number of bytes needed before we can determine whether we can
	// accept some bytes as a TLS 1.2 or 1.3 Client Hello.
	//
	// We read through to the client version, to have better assurance that we
	// don't accidentally match against something else.
	//
	//   Record header (5 bytes)
	//     16 - handshake record
	//     03 01 - protocol version 3.1 (TLS 1.0)
	//     XX XX - bytes of handshake message follows
	//
	//   Handshake header (4 bytes)
	//     01 - Client Hello
	//     XX XX XX - bytes of Client Hello follows
	//
	//   Client Version (2 bytes)
	//     03 03 - protocol version 3.3 (TLS 1.2)
	minTLSClientHelloLength_bytes = 11

	// Minimum number of bytes needed before we can determine whether we can
	// accept some bytes as a TLS 1.2 or 1.3 Server Hello.
	//
	// We read through to the server version, to have better assurance that we
	// don't accidentally match against something else.
	//
	//   Record header (5 bytes)
	//     16 - handshake record
	//     03 03 - protocol version 3.3 (TLS 1.2)
	//     XX XX - bytes of handshake message follows
	//
	//   Handshake header (4 bytes)
	//     02 - Server Hello
	//     XX XX XX - bytes of Client Hello follows
	//
	//   Server Version (2 bytes)
	//     03 03 - protocol version 3.3 (TLS 1.2)
	minTLSServerHelloLength_bytes = 11

	tlsRecordHeaderLength_bytes = 5
	handshakeHeaderLength_bytes = 4

	clientVersionLength_bytes = 2
	clientRandomLength_bytes  = 32

	serverVersionLength_bytes           = 2
	serverRandomLength_bytes            = 32
	serverCiphersuiteLength_bytes       = 2
	serverCompressionMethodLength_bytes = 1

	// Minimum number of bytes needed before we can determine whether we can
	// accept some bytes as a TLS ClientKeyExchange message.
	//
	// We read through to the encrypted pre-master secret length, to have better 
	// assurance that we don't accidentally match against something else.
	//
	//   Record header (5 bytes)
	//     16 - handshake record
	//     03 03 - protocol version 3.3 (TLS 1.2)
	//     XX XX - bytes of handshake message follows
	//
	//   Handshake header (4 bytes)
	//     10 - ClientKeyExchange
	//     XX XX XX - bytes of ClientKeyExchange follows
	//
	//   Pre-master secret length (2 bytes)
	//     XX XX - length of encrypted pre-master secret
	minTLSClientKeyExchangeLength_bytes = 11

	// TLS handshake message types
	tlsHandshakeTypeClientHello      = 0x01
	tlsHandshakeTypeServerHello      = 0x02
	tlsHandshakeTypeCertificate      = 0x0b
	tlsHandshakeTypeClientKeyExchange = 0x10
)

type tlsExtensionID uint16

const (
	serverNameTLSExtensionID        tlsExtensionID = 0x00_00
	alpnTLSExtensionID              tlsExtensionID = 0x00_10
	supportedVersionsTLSExtensionID tlsExtensionID = 0x00_2b
)

type sniType byte

const (
	dnsHostnameSNIType sniType = 0x00
)

var tlsVersionMap = map[uint16]akinet.TLSVersion{
	0x03_04: akinet.TLS_v1_3,
}
