package netutil

import "golang.org/x/net/bpf"

// Offsets within an Ethernet frame
const (
	offEtherType = 12 // EtherType field offset
	offIPProto   = 23 // IP protocol field (14 + 9)
	offDstMAC    = 0  // destination MAC starts at byte 0

	// IPv6 offsets (14-byte Ethernet + 40-byte fixed IPv6 header)
	offIP6NextHdr = 20 // IPv6 Next Header field (14 + 6)
	offIP6UDPSrc  = 54 // UDP src port over IPv6 (14 + 40 + 0)
	offIP6UDPDst  = 56 // UDP dst port over IPv6 (14 + 40 + 2)
)

// BPFFilterARP returns a BPF program that matches ARP frames (EtherType 0x0806).
func BPFFilterARP() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0806, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterDHCP returns a BPF program matching UDP port 67 or 68 (DHCP).
// EtherType==0x0800 && IP proto==17 && (srcPort==67||srcPort==68||dstPort==67||dstPort==68)
func BPFFilterDHCP() []bpf.RawInstruction {
	// IP header length is variable; we load it to compute UDP header offset.
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		// Check EtherType == IPv4
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 10},
		// Check IP protocol == UDP (17)
		bpf.LoadAbsolute{Off: offIPProto, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 8},
		// Load IP header length (IHL) to X
		bpf.LoadMemShift{Off: 14},
		// Load UDP src port (at 14 + IHL + 0)
		bpf.LoadIndirect{Off: 14, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipTrue: 4, SkipFalse: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 68, SkipTrue: 3, SkipFalse: 0},
		// Load UDP dst port (at 14 + IHL + 2)
		bpf.LoadIndirect{Off: 16, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipTrue: 1, SkipFalse: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 68, SkipTrue: 0, SkipFalse: 1},
		// Accept
		bpf.RetConstant{Val: 65536},
		// Reject
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterHSRP returns a BPF program matching UDP dst port 1985 (HSRP).
// EtherType==0x0800 && IP proto==17 && dstPort==1985
func BPFFilterHSRP() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 6},
		bpf.LoadAbsolute{Off: offIPProto, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 4},
		bpf.LoadMemShift{Off: 14},
		bpf.LoadIndirect{Off: 16, Size: 2}, // dst port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1985, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterVRRP returns a BPF program matching IP protocol 112 (VRRP).
// EtherType==0x0800 && IP proto==112
func BPFFilterVRRP() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 3},
		bpf.LoadAbsolute{Off: offIPProto, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 112, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterLLDP returns a BPF program matching LLDP frames (EtherType 0x88CC).
func BPFFilterLLDP() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x88CC, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterCDP returns a BPF program matching CDP frames (dst MAC 01:00:0c:cc:cc:cc).
func BPFFilterCDP() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		// Check first 4 bytes of dst MAC: 01:00:0c:cc
		bpf.LoadAbsolute{Off: offDstMAC, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x01000ccc, SkipTrue: 0, SkipFalse: 3},
		// Check last 2 bytes of dst MAC: cc:cc
		bpf.LoadAbsolute{Off: offDstMAC + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xcccc, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterNDP returns a BPF program matching NDP Neighbor Solicitation (135) and
// Neighbor Advertisement (136) packets.
// EtherType==0x86DD && NextHdr==58 (ICMPv6) && (type==135 || type==136)
func BPFFilterNDP() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 5},
		bpf.LoadAbsolute{Off: offIP6NextHdr, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 3}, // ICMPv6
		bpf.LoadAbsolute{Off: offIP6UDPSrc, Size: 1},                          // ICMPv6 type at offset 54
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 135, SkipTrue: 1, SkipFalse: 0}, // NS
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 136, SkipTrue: 0, SkipFalse: 1}, // NA
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterICMPv6 returns a BPF program matching all ICMPv6 packets.
// EtherType==0x86DD && NextHdr==58
func BPFFilterICMPv6() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 3},
		bpf.LoadAbsolute{Off: offIP6NextHdr, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 58, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterDHCPv6 returns a BPF program matching DHCPv6 packets.
// EtherType==0x86DD && NextHdr==17 (UDP) && (port==546 || port==547)
func BPFFilterDHCPv6() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 8},
		bpf.LoadAbsolute{Off: offIP6NextHdr, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 6}, // UDP
		bpf.LoadAbsolute{Off: offIP6UDPSrc, Size: 2},                          // src port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 546, SkipTrue: 3, SkipFalse: 0},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 547, SkipTrue: 2, SkipFalse: 0},
		bpf.LoadAbsolute{Off: offIP6UDPDst, Size: 2}, // dst port
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 546, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterHSRPv6 returns a BPF program matching HSRP over IPv6.
// EtherType==0x86DD && NextHdr==17 (UDP) && dstPort==1985
func BPFFilterHSRPv6() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 4},
		bpf.LoadAbsolute{Off: offIP6NextHdr, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 2},
		bpf.LoadAbsolute{Off: offIP6UDPDst, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1985, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterVRRPv6 returns a BPF program matching VRRP over IPv6.
// EtherType==0x86DD && NextHdr==112
func BPFFilterVRRPv6() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 3},
		bpf.LoadAbsolute{Off: offIP6NextHdr, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 112, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 65536},
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterHSRPDual returns a BPF program matching HSRP over both IPv4 and IPv6.
func BPFFilterHSRPDual() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		// 0: Load EtherType
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		// 1: IPv4? fall through : skip to 7 (check IPv6)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 5},
		// 2: Load IP protocol
		bpf.LoadAbsolute{Off: offIPProto, Size: 1},
		// 3: UDP(17)? fall through : skip to 13 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 9},
		// 4: Load IP header length
		bpf.LoadMemShift{Off: 14},
		// 5: Load UDP dst port
		bpf.LoadIndirect{Off: 16, Size: 2},
		// 6: port 1985? skip to 12 (accept) : skip to 13 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1985, SkipTrue: 5, SkipFalse: 6},
		// 7: IPv6? fall through : skip to 13 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 5},
		// 8: Load IPv6 Next Header
		bpf.LoadAbsolute{Off: offIP6NextHdr, Size: 1},
		// 9: UDP(17)? fall through : skip to 13 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 17, SkipTrue: 0, SkipFalse: 3},
		// 10: Load IPv6 UDP dst port
		bpf.LoadAbsolute{Off: offIP6UDPDst, Size: 2},
		// 11: port 1985? fall to 12 (accept) : skip to 13 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 1985, SkipTrue: 0, SkipFalse: 1},
		// 12: Accept
		bpf.RetConstant{Val: 65536},
		// 13: Reject
		bpf.RetConstant{Val: 0},
	})
	return instrs
}

// BPFFilterVRRPDual returns a BPF program matching VRRP over both IPv4 and IPv6.
func BPFFilterVRRPDual() []bpf.RawInstruction {
	instrs, _ := bpf.Assemble([]bpf.Instruction{
		// 0: Load EtherType
		bpf.LoadAbsolute{Off: offEtherType, Size: 2},
		// 1: IPv4? fall through : skip to 5 (check IPv6)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x0800, SkipTrue: 0, SkipFalse: 3},
		// 2: Load IP protocol
		bpf.LoadAbsolute{Off: offIPProto, Size: 1},
		// 3: VRRP(112)? skip to 7 (accept) : skip to 8 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 112, SkipTrue: 3, SkipFalse: 4},
		// 4: IPv6? fall through : skip to 8 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: 0, SkipFalse: 3},
		// 5: Load IPv6 Next Header
		bpf.LoadAbsolute{Off: offIP6NextHdr, Size: 1},
		// 6: VRRP(112)? fall to 7 (accept) : skip to 8 (reject)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 112, SkipTrue: 0, SkipFalse: 1},
		// 7: Accept
		bpf.RetConstant{Val: 65536},
		// 8: Reject
		bpf.RetConstant{Val: 0},
	})
	return instrs
}
