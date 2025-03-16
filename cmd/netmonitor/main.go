package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"grip/internal/capture"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	svcName = "NetMonitor"
	// Logging flags
	enablePacketLogs    bool
	enableInterfaceLogs bool
	enableDebugLogs     bool
)

func init() {
	// Add logging flags
	flag.BoolVar(&enablePacketLogs, "packet-logs", false, "Enable packet logging")
	flag.BoolVar(&enableInterfaceLogs, "interface-logs", false, "Enable network interface logging")
	flag.BoolVar(&enableDebugLogs, "debug-logs", true, "Enable debug logging")
}

func configureLogging() {
	capture.ConfigureLogging(capture.LogConfig{
		EnablePacketLogs:    enablePacketLogs,
		EnableInterfaceLogs: enableInterfaceLogs,
		EnableDebugLogs:     enableDebugLogs,
	})
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
	configureLogging()

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

	log.Printf("=== Network Statistics ===")
	log.Printf("Uptime: %v", uptime.Round(time.Second))
	log.Printf("Total Packets: %d", stats.TotalPackets.Load())
	log.Printf("Total Bytes: %d", stats.TotalBytes.Load())
	log.Printf("Packets/Second: %.2f", float64(stats.TotalPackets.Load())/uptime.Seconds())
	log.Printf("Bytes/Second: %.2f", float64(stats.TotalBytes.Load())/uptime.Seconds())

	log.Printf("Protocol Distribution:")
	stats.PacketsByProtocol.Range(func(key, value interface{}) bool {
		protocol := key.(string)
		count := value.(uint64)
		percentage := float64(count) / float64(stats.TotalPackets.Load()) * 100
		log.Printf("  %s: %d (%.1f%%)", protocol, count, percentage)
		return true
	})
	log.Printf("=====================")
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

	cmd := strings.ToLower(flag.Args()[0])
	switch cmd {
	case "debug":
		log.Printf("Starting in debug mode")
		configureLogging()
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
