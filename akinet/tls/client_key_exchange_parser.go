package tls

import (
	"errors"
	"time"

	"github.com/akitasoftware/akita-libs/akid"
	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/uuid"
)

func newTLSClientKeyExchangeParser(bidiID akinet.TCPBidiID) *tlsClientKeyExchangeParser {
	return &tlsClientKeyExchangeParser{
		connectionID: akid.NewConnectionID(uuid.UUID(bidiID)),
	}
}

type tlsClientKeyExchangeParser struct {
	connectionID akid.ConnectionID
	allInput     memview.MemView
}

var _ akinet.TCPParser = (*tlsClientKeyExchangeParser)(nil)

func (*tlsClientKeyExchangeParser) Name() string {
	return "TLS 1.2 ClientKeyExchange Parser"
}

func (parser *tlsClientKeyExchangeParser) Parse(input memview.MemView, isEnd bool) (result akinet.ParsedNetworkContent, unused memview.MemView, totalBytesConsumed int64, err error) {
	result, numBytesConsumed, err := parser.parse(input)
	
	// It's an error if we're at the end and we don't yet have a result.
	if isEnd && result == nil && err == nil {
		// We never got the full TLS record. This is an error.
		err = errors.New("incomplete TLS record for ClientKeyExchange")
	}

	totalBytesConsumed = parser.allInput.Len()

	if err != nil {
		return result, memview.MemView{}, totalBytesConsumed, err
	}

	if result != nil {
		unused = parser.allInput.SubView(numBytesConsumed, parser.allInput.Len())
		totalBytesConsumed -= unused.Len()
		return result, unused, totalBytesConsumed, nil
	}

	return nil, memview.MemView{}, totalBytesConsumed, nil
}

func (parser *tlsClientKeyExchangeParser) parse(input memview.MemView) (result akinet.ParsedNetworkContent, numBytesConsumed int64, err error) {
	// Add the incoming bytes to our buffer.
	parser.allInput.Append(input)

	// Wait until we have at least the TLS record header.
	if parser.allInput.Len() < tlsRecordHeaderLength_bytes {
		return nil, 0, nil
	}

	// Verify this is a handshake record (0x16)
	if parser.allInput.GetByte(0) != 0x16 {
		return nil, 0, errors.New("not a TLS handshake record")
	}

	// Get the TLS version from the record header
	version := parser.allInput.GetUint16(1)

	// The last two bytes of the record header give the total length of the
	// handshake message that appears after the record header.
	handshakeMsgLen_bytes := parser.allInput.GetUint16(tlsRecordHeaderLength_bytes - 2)
	handshakeMsgEndPos := int64(tlsRecordHeaderLength_bytes + handshakeMsgLen_bytes)

	// Wait until we have the full handshake record.
	if parser.allInput.Len() < handshakeMsgEndPos {
		return nil, 0, nil
	}

	// Verify this is a ClientKeyExchange message (0x10)
	handshakeType := parser.allInput.GetByte(tlsRecordHeaderLength_bytes)
	if handshakeType != tlsHandshakeTypeClientKeyExchange {
		return nil, 0, errors.New("not a ClientKeyExchange message")
	}

	// For RSA key exchange, the ClientKeyExchange message contains:
	// - 2 bytes: length of encrypted pre-master secret
	// - N bytes: encrypted pre-master secret
	
	preMasterSecretOffset := int64(tlsRecordHeaderLength_bytes + handshakeHeaderLength_bytes)
	if parser.allInput.Len() < preMasterSecretOffset+2 {
		return nil, 0, nil
	}

	// Get the length of the encrypted pre-master secret
	encryptedLength := int64(parser.allInput.GetUint16(preMasterSecretOffset))
	
	// Wait until we have the full encrypted pre-master secret
	if parser.allInput.Len() < preMasterSecretOffset+2+encryptedLength {
		return nil, 0, nil
	}

	// Extract the encrypted pre-master secret
	encryptedPreMasterSecret := make([]byte, encryptedLength)
	for i := int64(0); i < encryptedLength; i++ {
		encryptedPreMasterSecret[i] = parser.allInput.GetByte(preMasterSecretOffset + 2 + i)
	}

	clientKeyExchange := akinet.TLSClientKeyExchange{
		ConnectionID:             parser.connectionID,
		EncryptedPreMasterSecret: encryptedPreMasterSecret,
		Version:                  version,
		ObservationTime:          time.Now(),
	}

	return clientKeyExchange, handshakeMsgEndPos, nil
} 