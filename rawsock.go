package main

import (
	"errors"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const ethPAll = 0x0003 // ETH_P_ALL

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v >> 8)
}

// RawSocket wraps an AF_PACKET raw socket.
type RawSocket struct {
	fd      int
	ifIndex int
}

// NewRawSocket creates a new AF_PACKET raw socket bound to the named interface
// with promiscuous mode enabled and a 500ms receive timeout.
func NewRawSocket(ifaceName string) (*RawSocket, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, err
	}

	// Bind to the specific interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Enable promiscuous mode
	mreq := unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	// Set receive timeout (500ms, matching pcap behaviour)
	tv := syscall.Timeval{Sec: 0, Usec: 500000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return &RawSocket{fd: fd, ifIndex: iface.Index}, nil
}

// SetBPFFilter attaches a compiled BPF program to the socket via SO_ATTACH_FILTER.
func (r *RawSocket) SetBPFFilter(instrs []bpf.RawInstruction) error {
	if len(instrs) == 0 {
		return errors.New("empty BPF program")
	}

	prog := struct {
		Len    uint16
		_      [6]byte // padding
		Filter *bpf.RawInstruction
	}{
		Len:    uint16(len(instrs)),
		Filter: &instrs[0],
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(r.fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)),
		unsafe.Sizeof(prog),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// ReadPacket reads a single raw Ethernet frame from the socket.
// On timeout it returns nil, nil so callers can loop.
func (r *RawSocket) ReadPacket() ([]byte, error) {
	buf := make([]byte, 65536)
	n, _, err := syscall.Recvfrom(r.fd, buf, 0)
	if err != nil {
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil // timeout
		}
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return buf[:n], nil
}

// WritePacket sends a raw Ethernet frame on the bound interface.
func (r *RawSocket) WritePacket(data []byte) error {
	addr := syscall.SockaddrLinklayer{
		Ifindex: r.ifIndex,
	}
	return syscall.Sendto(r.fd, data, 0, &addr)
}

// Close closes the underlying file descriptor.
func (r *RawSocket) Close() {
	syscall.Close(r.fd)
}
