package oui

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type OUIDatabase struct {
	Vendors  map[string]string
	prefix2  map[[2]byte]string
	apiCache map[string]string
	apiMu    sync.Mutex
}

var ouiURLs = []string{
	"https://standards-oui.ieee.org/oui/oui.txt",
	"https://linuxnet.ca/ieee/oui.txt",
	"https://www.wireshark.org/download/automated/data/manuf",
}

var extendedOUIURLs = []struct {
	name  string
	url   string
	cache string
}{
	{"MA-M(28bit)", "https://standards-oui.ieee.org/oui28/mam.txt", "mam.txt"},
	{"MA-S(36bit)", "https://standards-oui.ieee.org/oui36/oui36.txt", "oui36.txt"},
}

const ouiMaxAge = 7 * 24 * time.Hour

func ouiCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".cache", "net-finder", "oui.txt")
}

func customOUIPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".config", "net-finder", "custom-oui.conf")
}

func apiCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".cache", "net-finder", "api-cache.txt")
}

const defaultCustomOUI = `# ============================================================
# IP Dup Finder - Custom MAC Vendor Mappings
# ============================================================
# 이 파일을 편집하여 커스텀 MAC 벤더 매핑을 추가/수정할 수 있습니다.
# 프로그램 재시작 없이 수정 내용이 다음 실행 시 반영됩니다.
#
# 형식: MAC_PREFIX<TAB>VENDOR_NAME
#   - 3바이트: XX:XX:XX	Vendor Name
#   - 2바이트: XX:XX	Vendor Name
#
# ---- 가상화 / 하이퍼바이저 ----
FA:16:3E	OpenStack/KVM (Neutron)
52:54:00	QEMU/KVM
FE:54:00	libvirt/KVM
BC:24:11	Proxmox VE
AC:DE:48	Private/KVM
# ---- 컨테이너 ----
02:42	Docker
02:00:00	systemd-container
# ---- 클라우드 ----
42:01:0A	Google Cloud
`

func LoadOUI() (*OUIDatabase, error) {
	db := &OUIDatabase{
		Vendors:  make(map[string]string),
		prefix2:  make(map[[2]byte]string),
		apiCache: make(map[string]string),
	}

	if err := db.loadIEEE(); err != nil {
		// IEEE OUI load failed, continue without it
		_ = err
	}

	db.loadExtendedIEEE()
	db.loadCustomConfig()
	db.loadAPICache()

	return db, nil
}

func (db *OUIDatabase) loadIEEE() error {
	cachePath := ouiCachePath()

	if info, err := os.Stat(cachePath); err == nil {
		if time.Since(info.ModTime()) < ouiMaxAge {
			return db.parseIEEEFile(cachePath)
		}
	}

	data, err := downloadOUI()
	if err != nil {
		if _, statErr := os.Stat(cachePath); statErr == nil {
			return db.parseIEEEFile(cachePath)
		}
		return err
	}

	dir := filepath.Dir(cachePath)
	if mkErr := os.MkdirAll(dir, 0755); mkErr == nil {
		os.WriteFile(cachePath, data, 0644)
	}

	return db.parseIEEEData(data)
}

func (db *OUIDatabase) loadExtendedIEEE() {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	cacheDir := filepath.Join(home, ".cache", "net-finder")

	client := &http.Client{Timeout: 60 * time.Second}

	for _, ext := range extendedOUIURLs {
		cachePath := filepath.Join(cacheDir, ext.cache)

		if info, err := os.Stat(cachePath); err == nil {
			if time.Since(info.ModTime()) < ouiMaxAge {
				if data, err := os.ReadFile(cachePath); err == nil {
					db.parseIEEEData(data)
					continue
				}
			}
		}

		req, err := http.NewRequest("GET", ext.url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		os.MkdirAll(cacheDir, 0755)
		os.WriteFile(cachePath, data, 0644)

		db.parseIEEEData(data)
	}
}

func downloadOUI() ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}

	var lastErr error
	for _, url := range ouiURLs {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
			continue
		}

		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		return data, nil
	}

	return nil, fmt.Errorf("모든 소스 실패: %v", lastErr)
}

func (db *OUIDatabase) parseIEEEFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return db.parseIEEEData(data)
}

func (db *OUIDatabase) parseIEEEData(data []byte) error {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "(hex)") {
			parts := strings.SplitN(line, "(hex)", 2)
			if len(parts) != 2 {
				continue
			}
			prefix := strings.TrimSpace(parts[0])
			prefix = strings.ReplaceAll(prefix, "-", ":")
			prefix = strings.ToUpper(prefix)
			vendor := strings.TrimSpace(parts[1])
			if vendor != "" {
				db.Vendors[prefix] = vendor
			}
			continue
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		prefix := strings.TrimSpace(fields[0])

		vendor := ""
		if len(fields) >= 3 && strings.TrimSpace(fields[2]) != "" {
			vendor = strings.TrimSpace(fields[2])
		} else {
			vendor = strings.TrimSpace(fields[1])
		}
		if vendor == "" {
			continue
		}

		if strings.Contains(prefix, "/") {
			slashParts := strings.SplitN(prefix, "/", 2)
			macBytes, err := net.ParseMAC(slashParts[0])
			if err != nil || len(macBytes) < 4 {
				continue
			}
			var key string
			switch slashParts[1] {
			case "28":
				key = fmt.Sprintf("%02X:%02X:%02X:%X", macBytes[0], macBytes[1], macBytes[2], macBytes[3]>>4)
			case "36":
				if len(macBytes) >= 5 {
					key = fmt.Sprintf("%02X:%02X:%02X:%02X:%X", macBytes[0], macBytes[1], macBytes[2], macBytes[3], macBytes[4]>>4)
				}
			default:
				continue
			}
			if key != "" {
				db.Vendors[key] = vendor
			}
			continue
		}

		if len(prefix) != 8 {
			continue
		}
		prefix = strings.ReplaceAll(prefix, "-", ":")
		prefix = strings.ToUpper(prefix)
		if _, exists := db.Vendors[prefix]; !exists {
			db.Vendors[prefix] = vendor
		}
	}

	return scanner.Err()
}

func (db *OUIDatabase) loadCustomConfig() {
	path := customOUIPath()

	if _, err := os.Stat(path); os.IsNotExist(err) {
		dir := filepath.Dir(path)
		if mkErr := os.MkdirAll(dir, 0755); mkErr == nil {
			os.WriteFile(path, []byte(defaultCustomOUI), 0644)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		fields := strings.SplitN(line, "\t", 2)
		if len(fields) != 2 {
			continue
		}

		prefix := strings.TrimSpace(fields[0])
		prefix = strings.ReplaceAll(prefix, "-", ":")
		prefix = strings.ToUpper(prefix)
		vendor := strings.TrimSpace(fields[1])

		if vendor == "" {
			continue
		}

		switch len(prefix) {
		case 8:
			db.Vendors[prefix] = vendor
		case 5:
			var key [2]byte
			_, err := fmt.Sscanf(prefix, "%02X:%02X", &key[0], &key[1])
			if err == nil {
				db.prefix2[key] = vendor
			}
		}
	}

}

func (db *OUIDatabase) loadAPICache() {
	path := apiCachePath()

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.SplitN(line, "\t", 2)
		if len(fields) == 2 {
			db.apiCache[strings.ToUpper(fields[0])] = fields[1]
		}
	}
}

func (db *OUIDatabase) saveAPICache() {
	db.apiMu.Lock()
	defer db.apiMu.Unlock()

	if len(db.apiCache) == 0 {
		return
	}

	path := apiCachePath()
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

	var sb strings.Builder
	sb.WriteString("# Auto-generated MAC Vendor API cache\n")
	for prefix, vendor := range db.apiCache {
		sb.WriteString(prefix)
		sb.WriteString("\t")
		sb.WriteString(vendor)
		sb.WriteString("\n")
	}
	os.WriteFile(path, []byte(sb.String()), 0644)
}

func (db *OUIDatabase) apiLookupMAC(mac net.HardwareAddr) string {
	prefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])

	db.apiMu.Lock()
	if v, ok := db.apiCache[prefix]; ok {
		db.apiMu.Unlock()
		return v
	}
	db.apiMu.Unlock()

	query := fmt.Sprintf("%02x-%02x-%02x", mac[0], mac[1], mac[2])
	urls := []string{
		"https://api.macvendors.com/" + query,
		"https://api.maclookup.app/v2/macs/" + query + "/company/name",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, url := range urls {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "net-finder/1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			vendor := strings.TrimSpace(string(body))
			if vendor != "" && vendor != "N/A" && vendor != "*NO COMPANY*" && !strings.Contains(vendor, "not found") {
				db.apiMu.Lock()
				db.apiCache[prefix] = vendor
				db.apiMu.Unlock()
				return vendor
			}
		}
	}

	db.apiMu.Lock()
	db.apiCache[prefix] = ""
	db.apiMu.Unlock()

	return ""
}

func isLocallyAdministered(mac net.HardwareAddr) bool {
	return len(mac) > 0 && mac[0]&0x02 != 0
}

func (db *OUIDatabase) Lookup(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return "Unknown"
	}

	// 36-bit MA-S (가장 구체적)
	if len(mac) >= 5 {
		key36 := fmt.Sprintf("%02X:%02X:%02X:%02X:%X", mac[0], mac[1], mac[2], mac[3], mac[4]>>4)
		if vendor, ok := db.Vendors[key36]; ok {
			return vendor
		}
	}

	// 28-bit MA-M
	if len(mac) >= 4 {
		key28 := fmt.Sprintf("%02X:%02X:%02X:%X", mac[0], mac[1], mac[2], mac[3]>>4)
		if vendor, ok := db.Vendors[key28]; ok {
			return vendor
		}
	}

	// 24-bit OUI
	prefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
	if vendor, ok := db.Vendors[prefix]; ok {
		if vendor != "IEEE Registration Authority" {
			return vendor
		}
	}

	// 2-byte 프리픽스 (Docker 등)
	key2 := [2]byte{mac[0], mac[1]}
	if vendor, ok := db.prefix2[key2]; ok {
		return vendor
	}

	// API 캐시 확인
	db.apiMu.Lock()
	if vendor, ok := db.apiCache[prefix]; ok {
		db.apiMu.Unlock()
		if vendor != "" {
			return vendor
		}
		if isLocallyAdministered(mac) {
			return "LAA(Virtual/Local)"
		}
		return "Unknown"
	}
	db.apiMu.Unlock()

	// 온라인 API 조회
	if vendor := db.apiLookupMAC(mac); vendor != "" {
		return vendor
	}

	if isLocallyAdministered(mac) {
		return "LAA(Virtual/Local)"
	}

	return "Unknown"
}

func (db *OUIDatabase) FormatMAC(mac net.HardwareAddr) string {
	if len(mac) < 6 {
		return mac.String()
	}
	vendor := db.Lookup(mac)
	macUpper := strings.ToUpper(mac.String())
	suffix := fmt.Sprintf("%02X:%02X:%02X", mac[3], mac[4], mac[5])
	return fmt.Sprintf("%s_%s (%s)", vendor, suffix, macUpper)
}
