package metrics

// Package metrics provides Prometheus metrics collection for DCA services.
//
// This package includes:
// - HTTP request metrics (count, latency, errors)
// - Metrics HTTP server on configurable port
// - Echo middleware for automatic request instrumentation
//
// Usage:
//   import "github.com/vultisig/dca/internal/metrics"
//
//   // Start metrics server
//   metricsServer := metrics.StartMetricsServer("88", logger)
//   defer metricsServer.Stop(context.Background())
//
//   // Add middleware to Echo
//   middlewares := append(server.DefaultMiddlewares(), metrics.HTTPMiddleware())
//   srv := server.NewServer(..., middlewares)