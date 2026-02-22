package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// ResolveHostnames resolves DNS PTR records for a list of IPs
// Uses a worker pool of 10 concurrent resolvers with 2s timeout per IP
func ResolveHostnames(ips []string) []HostnameEntry {
	if len(ips) == 0 {
		return nil
	}

	var mu sync.Mutex
	var results []HostnameEntry

	// Worker pool
	workers := 10
	if len(ips) < workers {
		workers = len(ips)
	}

	ch := make(chan string, len(ips))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resolver := &net.Resolver{}
			for ip := range ch {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				names, err := resolver.LookupAddr(ctx, ip)
				cancel()

				if err != nil || len(names) == 0 {
					continue
				}

				hostname := strings.TrimSuffix(names[0], ".")
				if hostname == "" {
					continue
				}

				mu.Lock()
				results = append(results, HostnameEntry{
					IP:       ip,
					Hostname: hostname,
				})
				mu.Unlock()
			}
		}()
	}

	for _, ip := range ips {
		ch <- ip
	}
	close(ch)
	wg.Wait()

	return results
}
