package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"net-finder/internal/alert"
	"net-finder/internal/models"
	"net-finder/internal/netutil"
	"net-finder/internal/protocol"
	"net-finder/internal/scanner"
	"net-finder/internal/server"
)

var version string

func main() {
	ifaceName := flag.String("i", "", "network interface (auto-detect if not specified)")
	subnetStr := flag.String("s", "", "subnets to scan (comma-separated, e.g. 192.168.1.0/24,10.0.0.0/24)")
	port := flag.Int("p", 9090, "web server port")
	autoScan := flag.Bool("auto", true, "auto scan on start")
	ipModeStr := flag.String("mode", "both", "IP version: ipv4, ipv6, both")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Net Finder\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  sudo %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  sudo %s -i eth0 -s 192.168.1.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s -p 9090\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s -auto=false\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s -mode ipv6\n", os.Args[0])
	}

	flag.Parse()

	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "This program requires root privileges. Please run with sudo.\n")
		os.Exit(1)
	}

	mode := models.ParseIPMode(*ipModeStr)

	// Get network interface
	iface, err := netutil.GetInterfaceForMode(*ifaceName, mode)
	if err != nil {
		log.Fatalf("Failed to detect interface: %v", err)
	}

	var localIP net.IP
	var localMAC net.HardwareAddr
	var subnets []*net.IPNet

	// IPv4 init (if mode != IPv6)
	if mode != models.IPModeIPv6 {
		localIP, localMAC, err = netutil.GetInterfaceAddr(iface)
		if err != nil {
			if mode == models.IPModeIPv4 {
				log.Fatalf("Failed to get interface address: %v", err)
			}
			log.Printf("No IPv4 address (proceeding with IPv6 only): %v", err)
		} else {
			if *subnetStr != "" {
				subnets = netutil.ParseSubnets(*subnetStr, iface)
			} else {
				subnets = netutil.ParseSubnets("", iface)
				discovered, err := protocol.DiscoverSubnets(iface, 5*time.Second)
				if err == nil {
					seen := make(map[string]bool)
					for _, s := range subnets {
						seen[s.String()] = true
					}
					for _, s := range discovered {
						if !seen[s.String()] {
							seen[s.String()] = true
							subnets = append(subnets, s)
						}
					}
				}
			}
		}
	}
	if localMAC == nil {
		localMAC = iface.HardwareAddr
	}

	// IPv6 init (if mode != IPv4)
	var localIPv6, linkLocalIPv6 net.IP
	var subnetsV6 []*net.IPNet
	if mode != models.IPModeIPv4 {
		globalIP, llIP, _, err := netutil.GetInterfaceAddrV6(iface)
		if err != nil {
			if mode == models.IPModeIPv6 {
				log.Fatalf("Failed to get IPv6 address: %v", err)
			}
			log.Printf("No IPv6 address (proceeding with IPv4 only): %v", err)
		} else {
			localIPv6 = globalIP
			linkLocalIPv6 = llIP
			subnetsV6 = netutil.ParseSubnetsV6(*subnetStr, iface)
		}
	}

	if len(subnets) == 0 && len(subnetsV6) == 0 {
		log.Fatal("No subnets to scan. Use -s option to specify subnets.")
	}

	var subnetStrs []string
	for _, s := range subnets {
		subnetStrs = append(subnetStrs, s.String())
	}
	for _, s := range subnetsV6 {
		subnetStrs = append(subnetStrs, s.String())
	}

	log.Printf("Mode: %s", mode)
	log.Printf("Interface: %s (MAC: %s)", iface.Name, localMAC)
	if localIP != nil {
		log.Printf("IPv4: %s", localIP)
	}
	if localIPv6 != nil {
		log.Printf("IPv6: %s", localIPv6)
	}
	if linkLocalIPv6 != nil {
		log.Printf("IPv6 link-local: %s", linkLocalIPv6)
	}
	log.Printf("Subnets: %s", strings.Join(subnetStrs, ", "))

	// Initialize alert manager and scanner
	alertMgr := alert.NewAlertManager()
	sc := scanner.NewScanner(iface, localIP, localIPv6, linkLocalIPv6, localMAC, subnets, subnetsV6, mode, alertMgr)

	if *autoScan {
		log.Println("Auto scan starting...")
		sc.Start()
	}

	// Try to open browser
	addr := fmt.Sprintf("http://localhost:%d", *port)
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(addr)
	}()

	log.Printf("Web server starting: %s", addr)
	if err := server.StartWebServer(*port, sc, alertMgr, iface.Name); err != nil {
		log.Fatalf("Web server failed: %v", err)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		return
	}
	cmd.Start()
}
