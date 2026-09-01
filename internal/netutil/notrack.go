package netutil

import (
	"fmt"
	"os/exec"
	"strings"
)

// Conntrack exemption for the SYN scan.
//
// Scan probes go out an AF_INET SOCK_RAW socket, so each one walks the kernel
// output path and conntrack allocates an entry for it. A full 1-65535 sweep is
// 65535 entries per host and each sits in SYN_SENT for
// nf_conntrack_tcp_timeout_syn_sent (120s by default), so the table fills long
// before the sweep ends and the kernel starts dropping packets that have
// nothing to do with the scan ("nf_conntrack: table full, dropping packet").
//
// The scan never needs those entries: replies are read straight off an
// AF_PACKET socket, not through the socket layer, and the scan keeps no state
// the kernel could help with. Exempting the scan's own source port is enough,
// and every other flow on the box stays tracked - NAT for containers and the
// like is untouched.
const notrackTable = "net_finder_notrack"

// InstallScanNotrack takes the scan's source port out of connection tracking.
// The table belongs to us alone, so tearing it down and rebuilding it cannot
// disturb rules anybody else put in place.
func InstallScanNotrack(port uint16) error {
	// Start from a clean slate. A table left behind by an earlier run would
	// otherwise collect a second copy of every rule.
	_ = exec.Command("nft", "delete", "table", "inet", notrackTable).Run()

	script := fmt.Sprintf(`table inet %[1]s {
	chain output {
		type filter hook output priority -300; policy accept;
		tcp sport %[2]d notrack
	}
	chain prerouting {
		type filter hook prerouting priority -300; policy accept;
		tcp dport %[2]d notrack
	}
}
`, notrackTable, port)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// RemoveScanNotrack puts the port back under connection tracking.
func RemoveScanNotrack() {
	_ = exec.Command("nft", "delete", "table", "inet", notrackTable).Run()
}
