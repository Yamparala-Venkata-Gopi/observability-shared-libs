package tls

import (
	"testing"

	"github.com/akitasoftware/akita-libs/akinet"
	"github.com/akitasoftware/akita-libs/memview"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestTLSClientKeyExchangeParserFactory(t *testing.T) {
	factory := NewTLSClientKeyExchangeParserFactory()
	
	// Just test that the factory exists and can be created
	assert.NotNil(t, factory)
	assert.Equal(t, "TLS 1.2 ClientKeyExchange Parser Factory", factory.Name())
}

func TestTLSClientKeyExchangeParser(t *testing.T) {
	bidiID := akinet.TCPBidiID(uuid.New())
	parser := newTLSClientKeyExchangeParser(bidiID)
	
	// Create a valid ClientKeyExchange message
	message := []byte{
		0x16,       // Handshake record type
		0x03, 0x03, // TLS 1.2 version
		0x00, 0x86, // Record length (134 bytes: 4 handshake header + 2 length + 128 data)
		0x10,       // ClientKeyExchange handshake type
		0x00, 0x00, 0x82, // Handshake message length (130 bytes: 2 length + 128 data)
		0x00, 0x80, // Encrypted pre-master secret length (128 bytes)
	}
	
	// Add 128 bytes of test encrypted data
	expectedSecret := make([]byte, 128)
	for i := 0; i < 128; i++ {
		expectedSecret[i] = byte(i)
		message = append(message, byte(i))
	}
	
	input := memview.New(message)
	result, unused, consumed, err := parser.Parse(input, true)
	
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, int64(len(message)), consumed)
	assert.Equal(t, int64(0), unused.Len())
	
	// Check that we got a TLSClientKeyExchange message
	keyExchange, ok := result.(akinet.TLSClientKeyExchange)
	assert.True(t, ok)
	assert.Equal(t, expectedSecret, keyExchange.EncryptedPreMasterSecret)
	assert.Equal(t, uint16(0x0303), keyExchange.Version)
} 