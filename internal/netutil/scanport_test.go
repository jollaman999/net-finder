package netutil

import (
	"fmt"
	"net"
	"testing"
)

func TestPickScanSrcPortIsAboveEphemeralRange(t *testing.T) {
	high := ephemeralHigh()

	port, err := PickScanSrcPort(0)
	if err != nil {
		t.Fatalf("PickScanSrcPort: %v", err)
	}

	if port <= high {
		t.Errorf("port %d is inside the ephemeral range (top %d); the kernel could hand it to another connection", port, high)
	}

	// Held for the life of the process, so a second bind has to fail.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err == nil {
		ln.Close()
		t.Errorf("port %d was still free after being picked", port)
	}
}

func TestPickScanSrcPortRefusesAnEphemeralPreference(t *testing.T) {
	// A port inside the ephemeral range must be refused however it is asked
	// for, since that is the case the picker exists to avoid.
	port, err := PickScanSrcPort(ephemeralHigh() - 1)
	if err != nil {
		t.Fatalf("PickScanSrcPort: %v", err)
	}

	if port == ephemeralHigh()-1 {
		t.Errorf("preferred port %d was taken despite being inside the ephemeral range", port)
	}
}
