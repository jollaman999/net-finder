package scanner

import (
	"testing"

	"net-finder/internal/models"
)

func TestClassifyConflicts(t *testing.T) {
	conflicts := []models.ConflictEntry{
		// 130.132-134: OpenStack VM MAC + a systematic 02:01:3f responder.
		// Same OUI set {02:01:3f, fa:16:3e} across 3 IPs -> oui_pair.
		{IP: "192.168.130.132", MACs: []string{"02:01:3f:e2:41:7d", "fa:16:3e:f3:30:9d"}},
		{IP: "192.168.130.133", MACs: []string{"02:01:3f:e2:41:7f", "fa:16:3e:13:6d:6a"}},
		{IP: "192.168.130.134", MACs: []string{"02:01:3f:e2:41:81", "fa:16:3e:9f:3c:1f"}},
		// 140.56/57: identical LAA MAC pair on both IPs -> shared_mac.
		{IP: "192.168.140.56", MACs: []string{"6a:ad:e8:86:9e:b4", "76:e0:fc:cd:be:c8"}},
		{IP: "192.168.140.57", MACs: []string{"6a:ad:e8:86:9e:b4", "76:e0:fc:cd:be:c8"}},
		// 140.180-183: Realtek + LCFC dual-NIC fleet. .180/.183 identical (shared_mac),
		// .181/.182 unique full MACs but same OUI set across the group (oui_pair).
		{IP: "192.168.140.180", MACs: []string{"00:e0:4c:a0:b4:48", "74:5d:22:f9:b4:56"}},
		{IP: "192.168.140.181", MACs: []string{"00:e0:4c:a0:b3:4c", "74:5d:22:f9:b3:dd"}},
		{IP: "192.168.140.182", MACs: []string{"00:e0:4c:a0:b4:29", "74:5d:22:f9:b4:13"}},
		{IP: "192.168.140.183", MACs: []string{"00:e0:4c:a0:b4:48", "74:5d:22:f9:b4:56"}},
		// Genuine collision: two unrelated global-vendor MACs, unique OUI set,
		// single IP -> stays "conflict".
		{IP: "10.0.0.5", MACs: []string{"00:11:22:33:44:55", "08:00:27:ab:cd:ef"}},
	}

	classifyConflicts(conflicts)

	want := map[string][2]string{
		"192.168.130.132": {"likely", "oui_pair"},
		"192.168.130.133": {"likely", "oui_pair"},
		"192.168.130.134": {"likely", "oui_pair"},
		"192.168.140.56":  {"likely", "shared_mac"},
		"192.168.140.57":  {"likely", "shared_mac"},
		"192.168.140.180": {"likely", "shared_mac"},
		"192.168.140.181": {"likely", "oui_pair"},
		"192.168.140.182": {"likely", "oui_pair"},
		"192.168.140.183": {"likely", "shared_mac"},
		"10.0.0.5":        {"conflict", ""},
	}
	for _, c := range conflicts {
		w := want[c.IP]
		if c.Kind != w[0] || c.Reason != w[1] {
			t.Errorf("%s: got kind=%q reason=%q, want kind=%q reason=%q",
				c.IP, c.Kind, c.Reason, w[0], w[1])
		}
	}
}
