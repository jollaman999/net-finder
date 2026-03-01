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
	"net-finder/internal/netutil"
	"net-finder/internal/protocol"
	"net-finder/internal/scanner"
	"net-finder/internal/server"
)

var version string

func main() {
	ifaceName := flag.String("i", "", "네트워크 인터페이스 (미지정시 자동 감지)")
	subnetStr := flag.String("s", "", "스캔할 서브넷 (콤마 구분, 예: 192.168.1.0/24,10.0.0.0/24)")
	port := flag.Int("p", 9090, "웹 서버 포트")
	autoScan := flag.Bool("auto", true, "시작 시 자동 스캔")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Net Finder\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  sudo %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  sudo %s -i eth0 -s 192.168.1.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s -p 9090\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s -auto=false\n", os.Args[0])
	}

	flag.Parse()

	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "이 프로그램은 root 권한이 필요합니다. sudo로 실행해주세요.\n")
		os.Exit(1)
	}

	// Get network interface
	iface, err := netutil.GetInterface(*ifaceName)
	if err != nil {
		log.Fatalf("인터페이스 감지 실패: %v", err)
	}

	localIP, localMAC, err := netutil.GetInterfaceAddr(iface)
	if err != nil {
		log.Fatalf("인터페이스 주소 가져오기 실패: %v", err)
	}

	// Parse subnets
	var subnets []*net.IPNet
	if *subnetStr != "" {
		subnets = netutil.ParseSubnets(*subnetStr, iface)
	} else {
		// Auto-discover from interface
		subnets = netutil.ParseSubnets("", iface)

		// Also try ARP-based discovery
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

	if len(subnets) == 0 {
		log.Fatal("스캔할 서브넷이 없습니다. -s 옵션으로 서브넷을 지정해주세요.")
	}

	subnetStrs := make([]string, len(subnets))
	for i, s := range subnets {
		subnetStrs[i] = s.String()
	}

	log.Printf("인터페이스: %s (%s, %s)", iface.Name, localIP, localMAC)
	log.Printf("서브넷: %s", strings.Join(subnetStrs, ", "))

	// Initialize alert manager and scanner
	alertMgr := alert.NewAlertManager()
	sc := scanner.NewScanner(iface, localIP, localMAC, subnets, alertMgr)

	if *autoScan {
		log.Println("자동 스캔 시작...")
		sc.Start()
	}

	// Try to open browser
	addr := fmt.Sprintf("http://localhost:%d", *port)
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(addr)
	}()

	log.Printf("웹 서버 시작: %s", addr)
	if err := server.StartWebServer(*port, sc, alertMgr, iface.Name); err != nil {
		log.Fatalf("웹 서버 실패: %v", err)
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
