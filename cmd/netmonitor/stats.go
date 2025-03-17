package main


import (
	"time"

	"grip/internal/capture"
	"grip/internal/logger"
)

func printStatistics() {
	stats := capture.GetStatistics()
	uptime := time.Since(stats.StartTime)

	logger.Info("=== Network Statistics ===")
	logger.Info("Uptime: %v", uptime.Round(time.Second))
	logger.Info("Total Packets: %d", stats.TotalPackets.Load())
	logger.Info("Total Bytes: %d", stats.TotalBytes.Load())
	logger.Info("Packets/Second: %.2f", float64(stats.TotalPackets.Load())/uptime.Seconds())
	logger.Info("Bytes/Second: %.2f", float64(stats.TotalBytes.Load())/uptime.Seconds())

	logger.Info("Protocol Distribution:")
	stats.PacketsByProtocol.Range(func(key, value interface{}) bool {
		protocol := key.(string)
		count := value.(uint64)
		percentage := float64(count) / float64(stats.TotalPackets.Load()) * 100
		logger.Info("  %s: %d (%.1f%%)", protocol, count, percentage)
		return true
	})

	// Get per-application statistics
	appStats := capture.GetApplicationStats()
	if len(appStats) > 0 {
		logger.Info("=== Application Statistics ===")

		for appName, app := range appStats {
			logger.Info("Application: %s (PID: %d)", appName, app.ProcessID)
			logger.Info("  Total Packets: %d", app.TotalPackets.Load())
			logger.Info("  Total Bytes: %d", app.TotalBytes.Load())

			// Protocol breakdown for this app
			logger.Info("  Protocol Distribution:")
			app.PacketsByProtocol.Range(func(key, value interface{}) bool {
				protocol := key.(string)
				count := value.(uint64)
				percentage := float64(count) / float64(app.TotalPackets.Load()) * 100
				logger.Info("    %s: %d (%.1f%%)", protocol, count, percentage)
				return true
			})

			// List destinations this app has connected to
			destinations := capture.GetDestinationsForApp(appName)
			if len(destinations) > 0 {
				logger.Info("  Connected to %d destinations:", len(destinations))

				// Limit to max 10 destinations in log to avoid spam
				maxDisplay := 10
				if len(destinations) < maxDisplay {
					maxDisplay = len(destinations)
				}

				for i := 0; i < maxDisplay; i++ {
					logger.Info("    %s", destinations[i])
				}

				if len(destinations) > maxDisplay {
					logger.Info("    ... and %d more", len(destinations)-maxDisplay)
				}
			}

			logger.Info("  ---------------------")
		}
	}

	logger.Info("=====================")
}
