package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	util "grip/internal"
	"grip/internal/capture"
	"grip/internal/logger"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
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

type netmonitor struct{}

func (m *netmonitor) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	// Configure logging
	if err := configureLogging(); err != nil {
		log.Printf("Failed to configure logging: %v", err)
		return true, 1
	}

	// Start packet capture
	if err := capture.StartCapture(); err != nil {
		log.Printf("Failed to start capture: %v", err)
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
			log.Printf("unexpected control request #%d", c)
		}
	}
	return
}

func printStatistics() {
	stats := capture.GetStatistics()
	uptime := time.Since(stats.StartTime)

	capture.LogInfo("=== Network Statistics ===")
	capture.LogInfo("Uptime: %v", uptime.Round(time.Second))
	capture.LogInfo("Total Packets: %d", stats.TotalPackets.Load())
	capture.LogInfo("Total Bytes: %d", stats.TotalBytes.Load())
	capture.LogInfo("Packets/Second: %.2f", float64(stats.TotalPackets.Load())/uptime.Seconds())
	capture.LogInfo("Bytes/Second: %.2f", float64(stats.TotalBytes.Load())/uptime.Seconds())

	capture.LogInfo("Protocol Distribution:")
	stats.PacketsByProtocol.Range(func(key, value interface{}) bool {
		protocol := key.(string)
		count := value.(uint64)
		percentage := float64(count) / float64(stats.TotalPackets.Load()) * 100
		capture.LogInfo("  %s: %d (%.1f%%)", protocol, count, percentage)
		return true
	})
	capture.LogInfo("=====================")
}

func runService(isDebug bool) {
	var err error
	if isDebug {
		err = debug.Run(svcName, &netmonitor{})
	} else {
		err = svc.Run(svcName, &netmonitor{})
	}
	if err != nil {
		log.Printf("Service failed: %v", err)
	}
}

func installService() error {
	exepath, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", svcName)
	}

	s, err = m.CreateService(svcName, exepath, mgr.Config{
		DisplayName: "Grip Network Monitor",
		Description: "Monitors and logs network traffic in real-time",
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return err
	}
	defer s.Close()

	err = eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("SetupEventLogSource() failed: %s", err)
	}

	return nil
}

func removeService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", svcName)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return err
	}

	err = eventlog.Remove(svcName)
	if err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}

	return nil
}

func main() {
	flag.Parse()

	if len(flag.Args()) < 1 {
		usage("no command specified")
	}

	// Check admin privileges first - do this before any other operations
	isAdmin, err := util.IsRunningAsAdmin()
	if err != nil {
		log.Fatalf("Failed to check administrator privileges: %v", err)
	}

	if !isAdmin {
		log.Fatalf("ADMINISTRATOR PRIVILEGES REQUIRED: This application requires administrator privileges to function properly. Please run as administrator.")
	}

	cmd := strings.ToLower(flag.Args()[0])
	switch cmd {
	case "debug":
		log.Printf("Starting in debug mode")
		if err := configureLogging(); err != nil {
			log.Fatalf("Failed to configure logging: %v", err)
		}
		if err := capture.StartCapture(); err != nil {
			log.Fatal(err)
		}
		// Wait indefinitely
		select {}
	case "install":
		err := installService()
		if err != nil {
			log.Fatalf("failed to install: %v", err)
		}
	case "remove":
		err := removeService()
		if err != nil {
			log.Fatalf("failed to remove: %v", err)
		}
	case "start", "stop", "pause", "continue":
		runService(false)
	default:
		usage(fmt.Sprintf("invalid command %s", cmd))
	}
}
