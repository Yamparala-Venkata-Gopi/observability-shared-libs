package tls

import (
	"fmt"
	"log"
	
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/gopacket/reassembly"
)

// NewTLSClientKeyExchangeParserFactory creates a new parser factory for TLS ClientKeyExchange messages
func NewTLSClientKeyExchangeParserFactory() akinet.TCPParserFactory {
	return &tlsClientKeyExchangeParserFactory{}
}

type tlsClientKeyExchangeParserFactory struct{}

var _ akinet.TCPParserFactory = (*tlsClientKeyExchangeParserFactory)(nil)

func (*tlsClientKeyExchangeParserFactory) Name() string {
	return "TLS 1.2 ClientKeyExchange Parser Factory"
}

func (f *tlsClientKeyExchangeParserFactory) Accepts(input memview.MemView, isEnd bool) (akinet.AcceptDecision, int64) {
	if input.Len() < minTLSClientKeyExchangeLength_bytes {
		if isEnd {
			return akinet.Reject, input.Len()
		}
		return akinet.NeedMoreData, 0
	}

	// Check if this looks like a TLS handshake record
	recordType := input.GetByte(0)
	if recordType != 0x16 {
		return akinet.Reject, input.Len()
	}

	// Check TLS version (we support TLS 1.2: 0x0303)
	version := input.GetUint16(1)
	if version != 0x0303 {
		return akinet.Reject, input.Len()
	}

	// Get the handshake message length
	handshakeMsgLen := input.GetUint16(3)
	
	// Check if we have enough data for the full handshake message
	if input.Len() < int64(5+handshakeMsgLen) {
		if isEnd {
			return akinet.Reject, input.Len()
		}
		return akinet.NeedMoreData, 0
	}

	// Check if this is a ClientKeyExchange message (0x10)
	handshakeType := input.GetByte(5)
	
	// Debug logging
	log.Printf("🔍 ClientKeyExchange Parser: recordType=0x%02x, version=0x%04x, handshakeType=0x%02x, expected=0x%02x", 
		recordType, version, handshakeType, tlsHandshakeTypeClientKeyExchange)
	
	if handshakeType != tlsHandshakeTypeClientKeyExchange {
		log.Printf("❌ ClientKeyExchange Parser: Rejecting - handshake type mismatch")
		return akinet.Reject, input.Len()
	}

	log.Printf("✅ ClientKeyExchange Parser: Accepting message")
	// This looks like a ClientKeyExchange message
	return akinet.Accept, 0
}

func (f *tlsClientKeyExchangeParserFactory) CreateParser(id akinet.TCPBidiID, seq, ack reassembly.Sequence) akinet.TCPParser {
	return newTLSClientKeyExchangeParser(id)
} 