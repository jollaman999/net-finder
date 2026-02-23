package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
)

//go:embed web/index.html
var webFS embed.FS

func startWebServer(port int, scanner *Scanner, alertMgr *AlertManager, currentIface string) error {
	mux := http.NewServeMux()

	// Serve SPA
	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		return fmt.Errorf("embed FS 오류: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(webSub)))

	// API endpoints
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetStatus())
	})

	mux.HandleFunc("/api/scan/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if scanner.IsRunning() {
			writeJSON(w, map[string]string{"error": "스캔이 이미 실행 중입니다"})
			return
		}
		scanner.Start()
		writeJSON(w, map[string]string{"status": "started"})
	})

	mux.HandleFunc("/api/scan/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		scanner.Stop()
		writeJSON(w, map[string]string{"status": "stopped"})
	})

	mux.HandleFunc("/api/hosts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetHosts())
	})

	mux.HandleFunc("/api/conflicts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetConflicts())
	})

	mux.HandleFunc("/api/dhcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetDHCPServers())
	})

	mux.HandleFunc("/api/hsrp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetHSRP())
	})

	mux.HandleFunc("/api/vrrp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetVRRP())
	})

	mux.HandleFunc("/api/lldp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetLLDP())
	})

	mux.HandleFunc("/api/cdp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetCDP())
	})

	mux.HandleFunc("/api/hostnames", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetHostnames())
	})

	mux.HandleFunc("/api/security/arp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetARPAlerts())
	})

	mux.HandleFunc("/api/security/dns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, scanner.GetDNSAlerts())
	})

	mux.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, GetInterfaces(currentIface))
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, alertMgr.GetConfigs())
		case http.MethodPost:
			var cfg AlertConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
			alertMgr.AddConfig(cfg)
			writeJSON(w, map[string]string{"status": "ok"})
		case http.MethodPut:
			var cfg AlertConfig
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, "Invalid JSON", http.StatusBadRequest)
				return
			}
			if cfg.ID == "" {
				http.Error(w, "id required", http.StatusBadRequest)
				return
			}
			if alertMgr.UpdateConfig(cfg) {
				writeJSON(w, map[string]string{"status": "ok"})
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			if id == "" {
				http.Error(w, "id required", http.StatusBadRequest)
				return
			}
			if alertMgr.DeleteConfig(id) {
				writeJSON(w, map[string]string{"status": "ok"})
			} else {
				http.Error(w, "not found", http.StatusNotFound)
			}
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/alerts/test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var cfg AlertConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if err := alertMgr.TestAlert(cfg); err != nil {
			writeJSON(w, map[string]interface{}{"status": "error", "message": err.Error()})
			return
		}
		writeJSON(w, map[string]string{"status": "ok"})
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: logMiddleware(mux),
	}

	return server.ListenAndServe()
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("JSON encode error: %v", err)
	}
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" && r.URL.Path != "/api/hosts" {
			log.Printf("%s %s", r.Method, r.URL.Path)
		}
		next.ServeHTTP(w, r)
	})
}
