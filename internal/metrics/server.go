package metrics

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Config holds metrics server configuration
type Config struct {
	Enabled bool   `mapstructure:"metrics_enabled" json:"metrics_enabled,omitempty"`
	Port    string `mapstructure:"metrics_port" json:"metrics_port,omitempty"`
}

// DefaultConfig returns default metrics configuration
func DefaultConfig() Config {
	return Config{
		Enabled: true,
		Port:    "88",
	}
}

// Server represents the metrics HTTP server
type Server struct {
	server *http.Server
	logger *logrus.Logger
}

// NewServer creates a new metrics server
func NewServer(addr string, logger *logrus.Logger) *Server {
	mux := http.NewServeMux()
	
	// Register the Prometheus metrics handler
	mux.Handle("/metrics", promhttp.Handler())
	
	// Add a health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:    ":" + addr,
		Handler: mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	return &Server{
		server: server,
		logger: logger,
	}
}

// Start starts the metrics server in a goroutine
func (s *Server) Start() {
	go func() {
		s.logger.Infof("Starting metrics server on %s", s.server.Addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Errorf("Metrics server failed to start: %v", err)
		}
	}()
}

// Stop gracefully shuts down the metrics server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Shutting down metrics server")
	return s.server.Shutdown(ctx)
}

// StartMetricsServer is a convenience function to start the metrics server
func StartMetricsServer(addr string, logger *logrus.Logger) *Server {
	// Register default Go runtime and process metrics only if not already registered
	if err := prometheus.Register(collectors.NewGoCollector()); err != nil {
		logger.Debugf("Go collector already registered: %v", err)
	}
	if err := prometheus.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
		logger.Debugf("Process collector already registered: %v", err)
	}

	server := NewServer(addr, logger)
	server.Start()
	return server
}