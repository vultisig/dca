package logging

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

// LogFormat represents the logging format type
type LogFormat string

const (
	FormatText LogFormat = "text"
	FormatJSON LogFormat = "json"
)

// UnmarshalText implements the encoding.TextUnmarshaler interface for type-safe config parsing
func (f *LogFormat) UnmarshalText(text []byte) error {
	value := LogFormat(strings.ToLower(string(text)))
	switch value {
	case FormatText, FormatJSON:
		*f = value
		return nil
	default:
		return fmt.Errorf("invalid log format %q, must be %q or %q", string(text), FormatText, FormatJSON)
	}
}

// NewLogger configures the global logrus logger and returns it
// This ensures all logrus usage in the process (including external dependencies) uses the same format
func NewLogger(format LogFormat) *logrus.Logger {
	if format == FormatJSON {
		// JSON formatter for production/VictoriaLogs
		logrus.SetFormatter(&logrus.JSONFormatter{
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyMsg: "_msg", // VictoriaLogs expects "_msg" field
			},
		})
	} else {
		// Text formatter for local development with colors
		logrus.SetFormatter(&logrus.TextFormatter{
			ForceColors: true,
		})
	}

	// Configure global logger settings
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.DebugLevel)

	return logrus.StandardLogger()
}
