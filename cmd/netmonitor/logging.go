package main

import (
	"fmt"
	"os"

	"grip/internal/capture"
	"grip/internal/logger"
)

// initMainLogger initializes the logger for the main package before capture is initialized
func initMainLogger() error {
	// Validate logging configuration
	if enableFile && logFilePath == "" {
		return fmt.Errorf("log file path must be specified when file logging is enabled")
	}

	// Create logger configuration
	config := logger.LoggerConfig{
		EnableError:   enableError,
		EnableWarning: enableWarning,
		EnableInfo:    enableInfo,
		EnableDebug:   enableDebug,
		EnableTrace:   enableTrace,
		EnableConsole: enableConsole,
		EnableFile:    enableFile,
		LogFilePath:   logFilePath,
		UseColors:     useColors,
	}

	// Initialize the logger package directly
	return logger.Initialize(config)
}

func configureLogging() error {
	// Validate logging configuration
	if enableFile && logFilePath == "" {
		return fmt.Errorf("log file path must be specified when file logging is enabled")
	}

	// Create logger configuration
	config := logger.LoggerConfig{
		EnableError:   enableError,
		EnableWarning: enableWarning,
		EnableInfo:    enableInfo,
		EnableDebug:   enableDebug,
		EnableTrace:   enableTrace,
		EnableConsole: enableConsole,
		EnableFile:    enableFile,
		LogFilePath:   logFilePath,
		UseColors:     useColors,
	}

	// Initialize the capture package logger
	return capture.InitializeLogger(config)
}

func usage(errmsg string) {
	fmt.Fprintf(os.Stderr,
		"%s\n\nusage: %s <command>\n"+
			"       where <command> is one of\n"+
			"       install, remove, debug, start, stop, pause or continue.\n",
		errmsg, os.Args[0])
	os.Exit(2)
}
