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

			method := c.Request().Method

			// Prefer route pattern; fall back to raw path for unregistered routes
			routePath := c.Path()
			if routePath == "" {
				routePath = c.Request().URL.Path
			}
			path := normalizePath(routePath)

			// Execute handler
			err := next(c)

			// Compute duration
			duration := time.Since(start).Seconds()

			// Derive final status code
			status := c.Response().Status

			// If handler returned an error, prefer its code
			if he, ok := err.(*echo.HTTPError); ok {
				status = he.Code
			}

			// Fallbacks if still unset
			if status == 0 {
				if err != nil {
					status = 500 // Internal server error
				} else {
					status = 200 // OK
				}
			}

			statusStr := strconv.Itoa(status)

			// Record metrics
			httpRequestsTotal.WithLabelValues(method, path, statusStr).Inc()
			httpRequestDuration.WithLabelValues(method, path).Observe(duration)

			// Record errors for non-2xx status codes (4xx + 5xx + weird 1xx/3xx)
			if status < 200 || status >= 300 {
				httpErrorsTotal.WithLabelValues(method, path, statusStr).Inc()
			}

			return err
		}
	}
}

// normalizePath returns the Echo route pattern to avoid high cardinality metrics
// Echo's c.Path() already provides the route pattern (e.g., "/users/:id") 
// rather than actual request paths (e.g., "/users/123"), so no transformation needed
func normalizePath(path string) string {
	if path == "" {
		return "unknown"
	}

	// Return the Echo route pattern as-is since it already contains placeholders
	return path
}