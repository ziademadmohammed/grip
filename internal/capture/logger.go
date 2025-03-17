package capture

import (
	"os"
	"time"

	"grip/internal/logger"
	"grip/internal/process"
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
	Direction   string    `json:"direction"`
	ProcessID   uint32    `json:"process_id,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
	ProcessPath string    `json:"process_path,omitempty"`
}

var (
	jsonLogFile *os.File
	jsonLogDir  = "logs"
)

// InitializeLogger sets up logging for the capture package
func InitializeLogger(config logger.LoggerConfig) error {
	// Initialize the core logger
	if err := logger.Initialize(config); err != nil {
		return err
	}

	// If we need to log to JSON files, set that up here
	if config.EnableFile {
		// Setup could go here if needed
	}

	return nil
}

// CloseLogger closes any open log files
func CloseLogger() {
	logger.Close()

	if jsonLogFile != nil {
		jsonLogFile.Close()
		jsonLogFile = nil
	}
}

// LogPacket handles packet logging with process information
func LogPacket(deviceName string, src, srcPort, dst, dstPort, protocol string, length int, direction string, procInfo *process.ProcessInfo) {
	// Skip if info logging is disabled
	if !logger.IsInfoEnabled() {
		return
	}

	if procInfo != nil {
		logger.Info("[%s] %s:%s -> %s:%s, Protocol: %s, Length: %d bytes, Direction: %s, Process: %s (%d) [%s]",
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
		logger.Info("[%s] %s:%s -> %s:%s, Protocol: %s, Length: %d bytes, Direction: %s",
			deviceName,
			src, srcPort,
			dst, dstPort,
			protocol,
			length,
			direction,
		)
	}

	// JSON packet logging could be added here if needed
}

// LogInterface logs information about network interfaces
func LogInterface(name, description string) {
	if !logger.IsInfoEnabled() {
		return
	}
	logger.Info("Found interface: %s (%s)", name, description)
}

// LogDebug logs debug information
func LogDebug(format string, v ...interface{}) {
	logger.Debug(format, v...)
}

// LogInfo logs information
func LogInfo(format string, v ...interface{}) {
	logger.Info(format, v...)
}

// LogError logs error information
func LogError(format string, v ...interface{}) {
	logger.Error(format, v...)
}

// LogWarning logs warning information
func LogWarning(format string, v ...interface{}) {
	logger.Warning(format, v...)
}
