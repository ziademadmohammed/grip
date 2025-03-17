package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	util "grip/internal"
	"grip/internal/capture"
	"grip/internal/database"
	"grip/internal/logger"

	"golang.org/x/sys/windows/svc"
)

var (
	svcName = "NetMonitor"

	// Log levels
	enableError   bool
	enableWarning bool
	enableInfo    bool
	enableDebug   bool
	enableTrace   bool

	// Log destinations
	enableConsole bool
	enableFile    bool
	logFilePath   string
	useColors     bool
)

func init() {
	// Log level flags
	flag.BoolVar(&enableError, "log-error", true, "Enable error logging")
	flag.BoolVar(&enableWarning, "log-warning", true, "Enable warning logging")
	flag.BoolVar(&enableInfo, "log-info", true, "Enable info logging")
	flag.BoolVar(&enableDebug, "log-debug", false, "Enable debug logging")
	flag.BoolVar(&enableTrace, "log-trace", false, "Enable trace logging")

	// Log destination flags
	flag.BoolVar(&enableConsole, "log-console", true, "Enable console logging")
	flag.BoolVar(&enableFile, "log-file", false, "Enable file logging")
	flag.StringVar(&logFilePath, "log-path", "logs/netmonitor.log", "Path to log file (if file logging enabled)")
	flag.BoolVar(&useColors, "log-colors", true, "Use colors in console output")
}

type netmonitor struct{}

func checkNpcapInstallation() {
	err := util.CheckNpcapInstallation()
	if err != nil {
		logger.Error("an Error occured while checking Npcap installation: %v", err)
		os.Exit(1)
	}

}

func initDatabase() {
	err := database.InitDatabase()
	if err != nil {
		logger.Error("an Error occured while initializing the database: %v", err)
		os.Exit(1)
	}
}

func (m *netmonitor) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	checkNpcapInstallation()
	initDatabase()

	// Configure logging
	if err := configureLogging(); err != nil {
		logger.Error("Failed to configure logging: %v", err)
		return true, 1
	}

	// Start packet capture
	if err := capture.StartCapture(); err != nil {
		logger.Error("Failed to start capture: %v", err)
		return true, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// Start statistics reporting in a goroutine
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			printStatistics()
		}
	}()

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			ticker.Stop()
			capture.StopCapture()
			printStatistics() // Print final statistics
			changes <- svc.Status{State: svc.StopPending}
			return
		case svc.Pause:
			changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
		case svc.Continue:
			changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
		default:
			logger.Warning("Unexpected control request #%d", c)
		}
	}
	return
}

func main() {
	flag.Parse()

	if len(flag.Args()) < 1 {
		usage("no command specified")
	}

	checkNpcapInstallation()
	initDatabase()

	// Initialize main logger before anything else
	if err := initMainLogger(); err != nil {
		fmt.Printf("FATAL: Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	command := strings.ToLower(flag.Args()[0])

	switch command {
	case "debug":
		logger.Info("Starting in debug mode")
		if err := configureLogging(); err != nil {
			logger.Error("Failed to configure logging: %v", err)
			os.Exit(1)
		}
		if err := capture.StartCapture(); err != nil {
			logger.Error("%v", err)
			os.Exit(1)
		}

		// Set up signal handling for graceful shutdown
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

		logger.Info("Press Ctrl+C to stop capturing")

		// Wait for termination signal
		<-signalChan

		logger.Info("Shutdown signal received, stopping capture...")

		// Print final statistics
		printStatistics()

		// Stop capture and close database
		capture.StopCapture()

		logger.Info("Shutdown complete")
		os.Exit(0)
	case "install":
		err := installService()
		if err != nil {
			logger.Error("Failed to install: %v", err)
			os.Exit(1)
		}
		logger.Info("Service installed successfully")
	case "remove":
		err := removeService()
		if err != nil {
			logger.Error("Failed to remove: %v", err)
			os.Exit(1)
		}
		logger.Info("Service removed successfully")
	case "start", "stop", "pause", "continue":
		runService(false)
	default:
		usage(fmt.Sprintf("invalid command %s", command))
	}
}
