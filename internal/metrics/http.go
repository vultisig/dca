package metrics

import (
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// HTTP request metrics
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "server",
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "dca",
			Subsystem: "server",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request latency in seconds",
			Buckets:   prometheus.DefBuckets, // Default: .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10
		},
		[]string{"method", "path"},
	)

	httpErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "dca",
			Subsystem: "server",
			Name:      "http_errors_total",
			Help:      "Total number of HTTP errors (status >= 500)",
		},
		[]string{"method", "path", "status"},
	)
)

// HTTPMiddleware returns Echo middleware for HTTP metrics collection
func HTTPMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			// Get request info
			method := c.Request().Method
			path := normalizePath(c.Path()) // Normalize to avoid high cardinality

			// Execute the request
			err := next(c)

			// Calculate duration
			duration := time.Since(start).Seconds()

			// Get response status
			status := strconv.Itoa(c.Response().Status)

			// Record metrics
			httpRequestsTotal.WithLabelValues(method, path, status).Inc()
			httpRequestDuration.WithLabelValues(method, path).Observe(duration)

			// Record errors for 5xx status codes
			if c.Response().Status >= 500 {
				httpErrorsTotal.WithLabelValues(method, path, status).Inc()
			}

			return err
		}
	}
}

// normalizePath normalizes Echo route paths to avoid high cardinality metrics
// Replaces dynamic segments with placeholders
func normalizePath(path string) string {
	if path == "" {
		return "unknown"
	}

	// Echo already provides the route pattern (e.g., "/users/:id")
	// which is perfect for metrics as it avoids high cardinality
	return path
}