
package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
)

func TestBuildTrojanAddr_IPv4(t *testing.T) {
	addr, err := buildTrojanAddr("1.2.3.4", 443)
	if err != nil {
		t.Fatal(err)
	}
	// ATYP=0x01 + 4 bytes IPv4 + 2 bytes port
	if len(addr) != 7 {
		t.Fatalf("expected length 7, got %d", len(addr))
	}
	if addr[0] != 0x01 {
		t.Fatalf("expected ATYP 0x01, got 0x%02x", addr[0])
	}
	if !net.IP(addr[1:5]).Equal(net.ParseIP("1.2.3.4").To4()) {
		t.Fatalf("unexpected IP: %v", addr[1:5])
	}
	if int(addr[5])<<8|int(addr[6]) != 443 {
		t.Fatalf("unexpected port")
	}
}

func TestBuildTrojanAddr_IPv6(t *testing.T) {
	addr, err := buildTrojanAddr("::1", 8080)
	if err != nil {
		t.Fatal(err)
	}
	if len(addr) != 19 {
		t.Fatalf("expected length 19, got %d", len(addr))
	}
	if addr[0] != 0x04 {
		t.Fatalf("expected ATYP 0x04, got 0x%02x", addr[0])
	}
}

func TestBuildTrojanAddr_Domain(t *testing.T) {
	addr, err := buildTrojanAddr("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	// ATYP=0x03 + 1 byte len + domain + 2 bytes port
	domain := "example.com"
	expected := 1 + 1 + len(domain) + 2
	if len(addr) != expected {
		t.Fatalf("expected length %d, got %d", expected, len(addr))
	}
	if addr[0] != 0x03 {
		t.Fatalf("expected ATYP 0x03, got 0x%02x", addr[0])
	}
	if addr[1] != byte(len(domain)) {
		t.Fatalf("expected domain length %d, got %d", len(domain), addr[1])
	}
	if string(addr[2:2+len(domain)]) != domain {
		t.Fatalf("unexpected domain: %s", addr[2:2+len(domain)])
	}
}

func TestTrojanPasswordHash(t *testing.T) {
	password := "test-password"
	hash := sha256.New224()
	hash.Write([]byte(password))
	var passHex [56]byte
	hex.Encode(passHex[:], hash.Sum(nil))

	// SHA-224 produces 28 bytes = 56 hex chars
	if len(passHex) != 56 {
		t.Fatalf("expected 56 hex chars, got %d", len(passHex))
	}
	// Verify it's valid hex
	_, err := hex.DecodeString(string(passHex[:]))
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
}

func TestTrojanHeaderFormat(t *testing.T) {
	password := "mypassword"
	hash := sha256.New224()
	hash.Write([]byte(password))
	var passHex [56]byte
	hex.Encode(passHex[:], hash.Sum(nil))

	addr, err := buildTrojanAddr("example.com", 443)
	if err != nil {
		t.Fatal(err)
	}

	// Build header as trojanConn.Write would
	headerLen := 56 + 2 + 1 + len(addr) + 2
	buf := make([]byte, headerLen)
	copy(buf, passHex[:])
	copy(buf[56:], []byte{0x0D, 0x0A})
	buf[58] = 0x01 // CMD: TCP CONNECT
	copy(buf[59:], addr)
	copy(buf[59+len(addr):], []byte{0x0D, 0x0A})

	// Verify structure
	if string(buf[:56]) != string(passHex[:]) {
		t.Fatal("password hash mismatch")
	}
	if buf[56] != 0x0D || buf[57] != 0x0A {
		t.Fatal("first CRLF mismatch")
	}
	if buf[58] != 0x01 {
		t.Fatal("CMD should be 0x01 for TCP CONNECT")
	}
	if buf[headerLen-2] != 0x0D || buf[headerLen-1] != 0x0A {
		t.Fatal("trailing CRLF mismatch")
	}
}
