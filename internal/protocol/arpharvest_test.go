package protocol

import (
	"net"
	"testing"

	"net-finder/internal/oui"
)

func isGlobalUnicast(mac net.HardwareAddr) bool { return mac[0]&0x03 == 0 }
func isLocallyAdmin(mac net.HardwareAddr) bool  { return mac[0]&0x02 != 0 }

// Synthetic MACs must carry the supplied real vendor OUI (first 3 octets) and be
// global-unicast, so they look like genuine devices.
func TestRandomMAC_UsesOUIPrefix(t *testing.T) {
	pool := [][3]byte{{0x00, 0x1A, 0x2B}, {0xB4, 0x2E, 0x99}}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		mac := randomMAC(pool)
		if len(mac) != 6 {
			t.Fatalf("bad length: %v", mac)
		}
		p := [3]byte{mac[0], mac[1], mac[2]}
		if p != pool[0] && p != pool[1] {
			t.Fatalf("MAC %v does not use a pool OUI", mac)
		}
		if !isGlobalUnicast(mac) {
			t.Fatalf("MAC %v is not global-unicast", mac)
		}
		seen[mac.String()] = true
	}
	if len(seen) < 100 {
		t.Fatalf("suffix not random enough: %d uniques", len(seen))
	}
}

// With no pool it falls back to a locally-administered address.
func TestRandomMAC_FallbackLAA(t *testing.T) {
	mac := randomMAC(nil)
	if !isLocallyAdmin(mac) {
		t.Fatalf("fallback MAC %v is not locally-administered", mac)
	}
}

// OUIPrefixes keeps only canonical 24-bit global-unicast prefixes.
func TestOUIPrefixesFilter(t *testing.T) {
	db := &oui.OUIDatabase{Vendors: map[string]string{
		"00:1A:2B":     "Vendor A",      // valid 24-bit
		"B4:2E:99":     "Vendor B",      // valid 24-bit
		"8C:1F:64:3":   "Vendor C (MA)", // 28-bit, must be skipped
		"02:11:22":     "Local",         // locally-administered, must be skipped
		"01:00:5E":     "Multicast",     // multicast, must be skipped
		"not-a-prefix": "junk",
	}}
	got := db.OUIPrefixes()
	if len(got) != 2 {
		t.Fatalf("expected 2 prefixes, got %d: %v", len(got), got)
	}
	for _, p := range got {
		if p[0]&0x03 != 0 {
			t.Fatalf("kept a non-global-unicast prefix: %v", p)
		}
	}
}
