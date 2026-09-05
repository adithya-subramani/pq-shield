package proxy

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

var (
	bufferPool32k = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32*1024)
			return &buf
		},
	}
)

type syncBufferPool struct{}

func (syncBufferPool) Get() []byte {
	ptr := bufferPool32k.Get().(*[]byte)
	return *ptr
}

func (syncBufferPool) Put(b []byte) {
	if cap(b) >= 32*1024 {
		b = b[:32*1024]
		bufferPool32k.Put(&b)
	}
}

func NewUpstreamProxy(targetURL string, upstreamTLS *tls.Config) (*httputil.ReverseProxy, error) {
	origin, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(origin)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		ReadBufferSize:        32 * 1024,
		WriteBufferSize:       32 * 1024,
	}

	if upstreamTLS != nil {
		transport.TLSClientConfig = upstreamTLS
	}

	proxy.Transport = transport
	proxy.BufferPool = syncBufferPool{}
	proxy.FlushInterval = -1

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		if req.Header.Get("X-Forwarded-Host") == "" {
			req.Header.Set("X-Forwarded-Host", req.Host)
		}

		host, _, splitErr := net.SplitHostPort(req.RemoteAddr)
		if splitErr != nil {
			host = req.RemoteAddr
		}
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			req.Header.Set("X-Forwarded-For", prior+", "+host)
		} else {
			req.Header.Set("X-Forwarded-For", host)
		}

		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-PQ-Shield", "hybrid-pqc-terminated")
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("Upstream proxy error",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"error", err,
		)
		http.Error(w, "Bad Gateway: Upstream Legacy Service Unreachable", http.StatusBadGateway)
	}

	return proxy, nil
}
