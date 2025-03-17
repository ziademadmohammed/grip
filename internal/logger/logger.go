package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Log levels
type LogLevel int

const (
	LevelError LogLevel = iota
	LevelWarning
	LevelInfo
	LevelDebug
	LevelTrace
)

// String representations of log levels
var levelStrings = map[LogLevel]string{
	LevelError:   "ERROR",
	LevelWarning: "WARN",
	LevelInfo:    "INFO",
	LevelDebug:   "DEBUG",
	LevelTrace:   "TRACE",
}

// Logger settings
var (
	// Log levels enabled
	errorEnabled   atomic.Bool
	warningEnabled atomic.Bool
	infoEnabled    atomic.Bool
	debugEnabled   atomic.Bool
	traceEnabled   atomic.Bool

	// Console output settings
	useColors      = true
	consoleEnabled atomic.Bool

	// File output settings
	logFile     *os.File
	logFilePath string
	fileEnabled atomic.Bool

	// Thread safety
	fileMutex sync.Mutex
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// LoggerConfig contains all logger configuration options
type LoggerConfig struct {
	EnableError   bool
	EnableWarning bool
	EnableInfo    bool
	EnableDebug   bool
	EnableTrace   bool
	EnableConsole bool
	EnableFile    bool
	LogFilePath   string
	UseColors     bool
}

// Initialize sets up the logger with the given configuration
func Initialize(config LoggerConfig) error {
	// Configure enabled log levels
	errorEnabled.Store(config.EnableError)
	warningEnabled.Store(config.EnableWarning)
	infoEnabled.Store(config.EnableInfo)
	debugEnabled.Store(config.EnableDebug)
	traceEnabled.Store(config.EnableTrace)

	// Configure outputs
	consoleEnabled.Store(config.EnableConsole)
	useColors = config.UseColors

	// Configure file logging if enabled
	if config.EnableFile {
		fileEnabled.Store(true)
		logFilePath = config.LogFilePath

		// Create log directory if it doesn't exist
		dir := filepath.Dir(logFilePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %v", err)
		}

		// Open log file
		file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %v", err)
		}
		logFile = file
	}

	// Log initialization
	Info("Logger initialized")
	return nil
}

// Close properly closes the logger and any open files
func Close() {
	if logFile != nil {
		fileMutex.Lock()
		defer fileMutex.Unlock()
		logFile.Close()
		logFile = nil
	}
}

// Helper to check if a log level is enabled
func isLevelEnabled(level LogLevel) bool {
	switch level {
	case LevelError:
		return errorEnabled.Load()
	case LevelWarning:
		return warningEnabled.Load()
	case LevelInfo:
		return infoEnabled.Load()
	case LevelDebug:
		return debugEnabled.Load()
	case LevelTrace:
		return traceEnabled.Load()
	default:
		return false
	}
}

// getColorCode returns the ANSI color code for a given log level
func getColorCode(level LogLevel) string {
	if !useColors {
		return ""
	}

	switch level {
	case LevelError:
		return colorRed
	case LevelWarning:
		return colorYellow
	case LevelInfo:
		return colorReset
	case LevelDebug:
		return colorBlue
	case LevelTrace:
		return colorGray
	default:
		return colorReset
	}
}

// formatMessage formats a log message with timestamp, level and message
func formatMessage(level LogLevel, format string, args ...interface{}) string {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	levelStr := levelStrings[level]
	message := fmt.Sprintf(format, args...)

	if consoleEnabled.Load() && useColors {
		colorCode := getColorCode(level)
		return fmt.Sprintf("%s [%s%s%s] %s", timestamp, colorCode, levelStr, colorReset, message)
	}

	return fmt.Sprintf("%s [%s] %s", timestamp, levelStr, message)
}

// logToConsole logs a message to the console if console logging is enabled
func logToConsole(message string) {
	if consoleEnabled.Load() {
		fmt.Println(message)
	}
}

// logToFile logs a message to the log file if file logging is enabled
func logToFile(message string) {
	if fileEnabled.Load() && logFile != nil {
		fileMutex.Lock()
		defer fileMutex.Unlock()
		fmt.Fprintln(logFile, message)
	}
}

// log logs a message at the specified level
func log(level LogLevel, format string, args ...interface{}) {
	if !isLevelEnabled(level) {
		return
	}

	message := formatMessage(level, format, args...)
	logToConsole(message)
	logToFile(message)
}

// Public logging functions

// Error logs an error message
func Error(format string, args ...interface{}) {
	log(LevelError, format, args...)
}

// Warning logs a warning message
func Warning(format string, args ...interface{}) {
	log(LevelWarning, format, args...)
}

// Info logs an informational message
func Info(format string, args ...interface{}) {
	log(LevelInfo, format, args...)
}

// Debug logs a debug message
func Debug(format string, args ...interface{}) {
	log(LevelDebug, format, args...)
}

// Trace logs a trace message (very detailed debugging)
func Trace(format string, args ...interface{}) {
	log(LevelTrace, format, args...)
}

// IsErrorEnabled returns whether error logging is enabled
func IsErrorEnabled() bool {
	return errorEnabled.Load()
}

// IsWarningEnabled returns whether warning logging is enabled
func IsWarningEnabled() bool {
	return warningEnabled.Load()
}

// IsInfoEnabled returns whether info logging is enabled
func IsInfoEnabled() bool {
	return infoEnabled.Load()
}

// IsDebugEnabled returns whether debug logging is enabled
func IsDebugEnabled() bool {
	return debugEnabled.Load()
}

// IsTraceEnabled returns whether trace logging is enabled
func IsTraceEnabled() bool {
	return traceEnabled.Load()
}
