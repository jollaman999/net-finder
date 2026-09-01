package netutil

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
)

// Choosing the SYN scan's source port.
//
// The conntrack exemption in notrack.go matches on the port number alone, so
// any other flow using that port loses connection tracking along with the
// scan - no NAT, and no match for the "ct state established,related accept"
// rule most firewalls are built on. Two things keep that from happening.
//
// The port is taken from above net.ipv4.ip_local_port_range, so the kernel
// will never hand it out as the source port of somebody else's outgoing
// connection. And the listener that proved it free is held open for the life
// of the process, so no service started afterwards can bind it either.
//
// Holding the listener costs the scan nothing. Replies are read off an
// AF_PACKET socket rather than through the socket layer, and a SYN-ACK that
// arrives for a listening socket is answered with a RST exactly as it is when
// nothing is bound at all.
//
// What this cannot cover is traffic merely passing through: a packet forwarded
// to some other host's copy of the port still meets the prerouting rule. Only
// the local side of the collision is solved here.
const (
	portRangeFile = "/proc/sys/net/ipv4/ip_local_port_range"

	// fallbackEphemeralHigh is the kernel's default upper bound, used when
	// the sysctl cannot be read.
	fallbackEphemeralHigh uint16 = 60999

	scanPortTries = 64
)

// scanPortHold keeps the chosen port bound. It is deliberately never closed:
// the port has to stay reserved for as long as a scan can run.
var scanPortHold net.Listener

// PickScanSrcPort returns a TCP port for the SYN scan to send from - above the
// local ephemeral range, free on this host, and held so nothing else can take
// it. preferred is tried first if it is above the range.
func PickScanSrcPort(preferred uint16) (uint16, error) {
	high := ephemeralHigh()
	if high >= 65535 {
		return 0, fmt.Errorf("ip_local_port_range ends at %d, leaving no port above it", high)
	}
	low := high + 1

	candidates := make([]uint16, 0, scanPortTries+1)
	if preferred >= low {
		candidates = append(candidates, preferred)
	}
	span := int(65535-low) + 1
	for len(candidates) < cap(candidates) {
		candidates = append(candidates, low+uint16(rand.Intn(span)))
	}

	for _, port := range candidates {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue
		}

		scanPortHold = ln
		go drainHold(ln)

		return port, nil
	}

	return 0, fmt.Errorf("no free TCP port above %d after %d tries", high, len(candidates))
}

// drainHold closes anything that connects to the held port, so a peer knocking
// on it cannot fill the accept queue.
func drainHold(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}
}

// ephemeralHigh reports the top of the range the kernel picks source ports from.
func ephemeralHigh() uint16 {
	data, err := os.ReadFile(portRangeFile)
	if err != nil {
		return fallbackEphemeralHigh
	}

	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return fallbackEphemeralHigh
	}

	high, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return fallbackEphemeralHigh
	}

	return uint16(high)
}
