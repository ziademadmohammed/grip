package capture

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

type PacketLog struct {
	Timestamp   time.Time `json:"timestamp"`
	Device      string    `json:"device"`
	SrcIP       string    `json:"src_ip"`
	SrcPort     string    `json:"src_port"`
	DstIP       string    `json:"dst_ip"`
	DstPort     string    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	Length      int       `json:"length"`
	ProcessID   uint32    `json:"process_id,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
	ProcessPath string    `json:"process_path,omitempty"`
}

var (
	logFile *os.File
	logDir  = "logs"

	// Feature flags for different types of logging
	packetLoggingEnabled    atomic.Bool
	interfaceLoggingEnabled atomic.Bool
	debugLoggingEnabled     atomic.Bool
)

// LogConfig holds the configuration for different types of logging
type LogConfig struct {
	EnablePacketLogs    bool
	EnableInterfaceLogs bool
	EnableDebugLogs     bool
}

// ConfigureLogging sets up the logging configuration
func ConfigureLogging(config LogConfig) {
	packetLoggingEnabled.Store(config.EnablePacketLogs)
	interfaceLoggingEnabled.Store(config.EnableInterfaceLogs)
	debugLoggingEnabled.Store(config.EnableDebugLogs)
}

func initLogger() error {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Create a new log file for this session
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	logPath := filepath.Join(logDir, fmt.Sprintf("network_traffic_%s.log", timestamp))

	file, err := os.Create(logPath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %v", err)
	}

	logFile = file
	return nil
}

func closeLogger() {
	if logFile != nil {
		logFile.Close()
	}
}

func logToFile(entry PacketLog) {
	if logFile == nil {
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		fmt.Printf("Error marshaling packet log: %v\n", err)
		return
	}

	logFile.Write(data)
	logFile.Write([]byte("\n"))
}

// LogPacket handles packet logging with process information
func LogPacket(deviceName string, src, srcPort, dst, dstPort, protocol string, length int, direction string, procInfo *ProcessInfo) {
	if !packetLoggingEnabled.Load() {
		return
	}

	if procInfo != nil {
		log.Printf("[%s] %s:%s -> %s:%s, Protocol: %s, Length: %d bytes, Direction: %s, Process: %s (%d) [%s]",
			deviceName,
			src, srcPort,
			dst, dstPort,
			protocol,
			length,
			direction,
			procInfo.ProcessName,
			procInfo.ProcessID,
			procInfo.ExecutablePath,
		)
	} else {
		log.Printf("[%s] %s:%s -> %s:%s, Protocol: %s, Length: %d bytes, Direction: %s",
			deviceName,
			src, srcPort,
			dst, dstPort,
			protocol,
			length,
			direction,
		)
	}
}

// LogInterface logs information about network interfaces
func LogInterface(name, description string) {
	if !interfaceLoggingEnabled.Load() {
		return
	}
	log.Printf("Found interface: %s (%s)", name, description)
}

// LogDebug logs debug information
func LogDebug(format string, v ...interface{}) {
	if !debugLoggingEnabled.Load() {
		return
	}
	log.Printf(format, v...)
}

// IsPacketLoggingEnabled returns the current state of packet logging
func IsPacketLoggingEnabled() bool {
	return packetLoggingEnabled.Load()
}

// IsInterfaceLoggingEnabled returns the current state of interface logging
func IsInterfaceLoggingEnabled() bool {
	return interfaceLoggingEnabled.Load()
}

// IsDebugLoggingEnabled returns the current state of debug logging
func IsDebugLoggingEnabled() bool {
	return debugLoggingEnabled.Load()
}
