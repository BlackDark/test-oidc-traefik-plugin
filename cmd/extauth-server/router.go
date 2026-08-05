package main

import (
	"net/http"
	"strings"
	"sync/atomic"
)

type hostRouter struct {
	hosts atomic.Pointer[map[string]http.Handler]
}

func newHostRouter() *hostRouter {
	r := &hostRouter{}
	empty := map[string]http.Handler{}
	r.hosts.Store(&empty)
	return r
}

func (r *hostRouter) swap(m map[string]http.Handler) {
	r.hosts.Store(&m)
}

func (r *hostRouter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m := *r.hosts.Load()
	h, ok := lookupHost(m, req.Host)
	if !ok {
		http.Error(rw, "unknown host", http.StatusForbidden)
		return
	}
	h.ServeHTTP(rw, req)
}

// lookupHost prefers exact Host match, then longest *.suffix wildcard.
func lookupHost(m map[string]http.Handler, host string) (http.Handler, bool) {
	host = normalizeHost(host)
	if h, ok := m[host]; ok {
		return h, true
	}

	var best string
	var bestH http.Handler
	for pattern, h := range m {
		if !strings.HasPrefix(pattern, "*.") {
			continue
		}
		suffix := pattern[1:] // ".example.com"
		if !strings.HasSuffix(host, suffix) || len(host) <= len(suffix) {
			continue
		}
		if len(pattern) >= len(best) {
			best = pattern
			bestH = h
		}
	}
	if best == "" {
		return nil, false
	}
	return bestH, true
}
