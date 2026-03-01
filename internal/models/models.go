package models

import (
	"net"
	"sync"
)

// ProgressInfo represents scan progress
type ProgressInfo struct {
	Phase   string `json:"phase"`
	Percent int    `json:"percent"`
	Count   int    `json:"count,omitempty"`
}

// HostEntry represents a discovered host
type HostEntry struct {
	IP          string   `json:"ip"`
	Hostname    string   `json:"hostname"`
	MAC         string   `json:"mac"`
	Vendor      string   `json:"vendor"`
	Subnet      string   `json:"subnet"`
	IsBond      bool     `json:"isBond,omitempty"`
	BondMACs    []string `json:"bondMACs,omitempty"`
	BondVendors []string `json:"bondVendors,omitempty"`
}

// ConflictEntry represents an IP conflict
type ConflictEntry struct {
	IP       string   `json:"ip"`
	Hostname string   `json:"hostname"`
	MACs     []string `json:"macs"`
	Vendors  []string `json:"vendors"`
	Subnet   string   `json:"subnet"`
}

// DHCPServerJSON is the JSON-friendly DHCP server info
type DHCPServerJSON struct {
	ServerIP   string   `json:"serverIP"`
	ServerMAC  string   `json:"serverMAC"`
	Vendor     string   `json:"vendor"`
	OfferedIP  string   `json:"offeredIP"`
	SubnetMask string   `json:"subnetMask"`
	Router     string   `json:"router"`
	DNS        []string `json:"dns"`
	LeaseTime  uint32   `json:"leaseTime"`
}

// DHCPServerInfo holds raw DHCP server data
type DHCPServerInfo struct {
	ServerIP   net.IP
	ServerMAC  net.HardwareAddr
	OfferedIP  net.IP
	SubnetMask net.IPMask
	Router     net.IP
	DNS        []net.IP
	LeaseTime  uint32
}

// HSRPEntry represents an HSRP advertisement
type HSRPEntry struct {
	Version   int    `json:"version"`
	Group     int    `json:"group"`
	Priority  int    `json:"priority"`
	State     string `json:"state"`
	VirtualIP string `json:"virtualIP"`
	HelloTime int    `json:"helloTime"`
	HoldTime  int    `json:"holdTime"`
	SourceIP  string `json:"sourceIP"`
	SourceMAC string `json:"sourceMAC"`
	Timestamp string `json:"timestamp"`
}

// VRRPEntry represents a VRRP advertisement
type VRRPEntry struct {
	Version     int      `json:"version"`
	RouterID    int      `json:"routerID"`
	Priority    int      `json:"priority"`
	IPAddresses []string `json:"ipAddresses"`
	AdverInt    int      `json:"adverInt"`
	SourceIP    string   `json:"sourceIP"`
	SourceMAC   string   `json:"sourceMAC"`
	Timestamp   string   `json:"timestamp"`
}

// LLDPNeighbor represents an LLDP neighbor
type LLDPNeighbor struct {
	ChassisID string `json:"chassisID"`
	PortID    string `json:"portID"`
	SysName   string `json:"sysName"`
	SysDesc   string `json:"sysDesc"`
	MgmtAddr  string `json:"mgmtAddr"`
	TTL       int    `json:"ttl"`
	SourceMAC string `json:"sourceMAC"`
	Timestamp string `json:"timestamp"`
}

// CDPNeighbor represents a CDP neighbor
type CDPNeighbor struct {
	DeviceID   string   `json:"deviceID"`
	Addresses  []string `json:"addresses"`
	PortID     string   `json:"portID"`
	Platform   string   `json:"platform"`
	Version    string   `json:"version"`
	NativeVLAN int      `json:"nativeVLAN"`
	SourceMAC  string   `json:"sourceMAC"`
	Timestamp  string   `json:"timestamp"`
}

// HostnameEntry maps IP to hostname
type HostnameEntry struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// ARPSpoofAlert represents an ARP spoofing alert
type ARPSpoofAlert struct {
	IP        string `json:"ip"`
	OldMAC    string `json:"oldMAC"`
	NewMAC    string `json:"newMAC"`
	AlertType string `json:"alertType"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Count     int    `json:"count"`
	FirstSeen string `json:"firstSeen"`
	Timestamp string `json:"timestamp"`
	Subnet    string `json:"subnet"`
}

// DNSSpoofAlert represents a DNS spoofing alert
type DNSSpoofAlert struct {
	Domain    string `json:"domain"`
	Server1   string `json:"server1"`
	Response1 string `json:"response1"`
	Server2   string `json:"server2"`
	Response2 string `json:"response2"`
	AlertType string `json:"alertType"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

// ScanState holds all scan results
type ScanState struct {
	Mu            sync.RWMutex     `json:"-"`
	Status        string           `json:"status"`
	Progress      ProgressInfo     `json:"progress"`
	Hosts         []HostEntry      `json:"hosts"`
	Conflicts     []ConflictEntry  `json:"conflicts"`
	DHCPServers   []DHCPServerJSON `json:"dhcpServers"`
	HSRPEntries   []HSRPEntry      `json:"hsrpEntries"`
	VRRPEntries   []VRRPEntry      `json:"vrrpEntries"`
	LLDPNeighbors []LLDPNeighbor   `json:"lldpNeighbors"`
	CDPNeighbors  []CDPNeighbor    `json:"cdpNeighbors"`
	Hostnames     []HostnameEntry  `json:"hostnames"`
	ARPAlerts     []ARPSpoofAlert  `json:"arpAlerts"`
	DNSAlerts     []DNSSpoofAlert  `json:"dnsAlerts"`
}

// InterfaceInfo for the API
type InterfaceInfo struct {
	Name    string   `json:"name"`
	MAC     string   `json:"mac"`
	IPs     []string `json:"ips"`
	Up      bool     `json:"up"`
	Current bool     `json:"current"`
}

// AlertConfig represents a single alert rule
type AlertConfig struct {
	ID       string   `json:"id"`
	Subnets  []string `json:"subnets"`          // monitored subnets (empty = all)
	Events   []string `json:"events,omitempty"` // monitored events (empty = all)
	Type     string   `json:"type"`             // "email"
	SmtpHost string   `json:"smtpHost,omitempty"`
	SmtpPort int      `json:"smtpPort,omitempty"`
	SmtpFrom string   `json:"smtpFrom,omitempty"` // sender address (From)
	SmtpTo   string   `json:"smtpTo,omitempty"`
	SmtpSSL  bool     `json:"smtpSSL,omitempty"`
	SmtpAuth bool     `json:"smtpAuth,omitempty"`
	SmtpUser string   `json:"smtpUser,omitempty"` // auth credentials
	SmtpPass string   `json:"smtpPass,omitempty"`
}
