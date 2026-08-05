package main

import (
	"net/http"
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
	h, ok := m[normalizeHost(req.Host)]
	if !ok {
		http.Error(rw, "unknown host", http.StatusForbidden)
		return
	}
	h.ServeHTTP(rw, req)
}
