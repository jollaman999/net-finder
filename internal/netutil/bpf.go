package netutil

import "golang.org/x/net/bpf"

// Offsets within an Ethernet frame
const (
	offEtherType = 12 // EtherType field offset
	offIPProto   = 23 // IP protocol field (14 + 9)
	offDstMAC    = 0  // destination MAC starts at byte 0
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
