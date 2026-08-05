package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHostRouter_RoutesByHost(t *testing.T) {
	var hitA, hitB atomic.Int32
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hitA.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
		"b.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hitB.Add(1)
			w.WriteHeader(http.StatusAccepted)
		}),
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://a.example.com/x", nil)
	req.Host = "A.example.com:443"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK || hitA.Load() != 1 {
		t.Fatalf("A: code=%d hitA=%d", rw.Code, hitA.Load())
	}

	rw = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://b.example.com/x", nil)
	req.Host = "b.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusAccepted || hitB.Load() != 1 {
		t.Fatalf("B: code=%d hitB=%d", rw.Code, hitB.Load())
	}
}

func TestHostRouter_UnknownHostForbidden(t *testing.T) {
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://unknown.example.com/", nil)
	req.Host = "unknown.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rw.Code)
	}
}

func TestHostRouter_SwapAtomic(t *testing.T) {
	r := newHostRouter()
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	})
	r.swap(map[string]http.Handler{
		"a.example.com": http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
	})

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://a.example.com/", nil)
	req.Host = "a.example.com"
	r.ServeHTTP(rw, req)
	if rw.Code != http.StatusTeapot {
		t.Fatalf("status=%d want 418 after swap", rw.Code)
	}
}
