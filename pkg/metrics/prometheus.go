package metrics

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	once     sync.Once
	instance *Engine
)

type Engine struct {
	registry                  *prometheus.Registry
	handshakeTotal            *prometheus.CounterVec
	downgradeAttemptsTotal    prometheus.Counter
	handshakeDuration         prometheus.Histogram
	pqcClientHelloCapable     prometheus.Counter
	classicClientHelloCapable prometheus.Counter
}

func Get() *Engine {
	once.Do(func() {
		instance = &Engine{
			registry: prometheus.NewRegistry(),
		}
		instance.initMetrics()
	})
	return instance
}

func (e *Engine) initMetrics() {
	e.handshakeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pqshield_handshake_total",
			Help: "Total TLS handshakes completed labeled by pqc_negotiated=true|false.",
		},
		[]string{"pqc_negotiated"},
	)
	e.registry.MustRegister(e.handshakeTotal)

	e.downgradeAttemptsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pqshield_downgrade_attempts_total",
			Help: "Clients that advertised PQC in ClientHello but resolved to Classical TLS.",
		},
	)
	e.registry.MustRegister(e.downgradeAttemptsTotal)

	e.handshakeDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "pqshield_handshake_duration_seconds",
			Help:    "Latency distribution of TLS 1.3 handshakes.",
			Buckets: []float64{0.0005, 0.001, 0.002, 0.005, 0.01},
		},
	)
	e.registry.MustRegister(e.handshakeDuration)

	e.pqcClientHelloCapable = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pqshield_client_hello_pqc_capable_total",
			Help: "Number of ClientHello messages advertising X25519MLKEM768 support.",
		},
	)
	e.registry.MustRegister(e.pqcClientHelloCapable)

	e.classicClientHelloCapable = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "pqshield_client_hello_classic_only_total",
			Help: "Number of ClientHello messages without PQC curve support.",
		},
	)
	e.registry.MustRegister(e.classicClientHelloCapable)
}

func (e *Engine) Handler() http.Handler {
	return promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{})
}

func RecordClientHello(hasPQCCapability bool) {
	e := Get()
	if hasPQCCapability {
		e.pqcClientHelloCapable.Inc()
	} else {
		e.classicClientHelloCapable.Inc()
	}
}

type HandshakeRecorder struct {
	Start          time.Time
	ClientPQCAware bool
	HandshakeDone  chan struct{}
	once           sync.Once
}

func NewHandshakeRecorder(clientPQCAware bool) *HandshakeRecorder {
	return &HandshakeRecorder{
		Start:          time.Now(),
		ClientPQCAware: clientPQCAware,
		HandshakeDone:  make(chan struct{}),
	}
}

func (r *HandshakeRecorder) Complete(state tls.ConnectionState) {
	r.once.Do(func() {
		defer close(r.HandshakeDone)

		e := Get()
		duration := time.Since(r.Start).Seconds()
		e.handshakeDuration.Observe(duration)

		negotiatedPQC := r.inferNegotiatedPQC(state)

		if negotiatedPQC {
			e.handshakeTotal.WithLabelValues("true").Inc()
		} else {
			e.handshakeTotal.WithLabelValues("false").Inc()
			if r.ClientPQCAware {
				e.downgradeAttemptsTotal.Inc()
				slog.Warn("SECURITY_DOWNGRADE_ALERT: client advertised PQC capability but resolved to classical curve",
					"tls_version", state.Version,
					"cipher_suite", state.CipherSuite,
					"duration_seconds", duration,
				)
			}
		}
	})
}

func (r *HandshakeRecorder) inferNegotiatedPQC(state tls.ConnectionState) bool {
	if state.Version < tls.VersionTLS13 {
		return false
	}
	return r.ClientPQCAware
}
