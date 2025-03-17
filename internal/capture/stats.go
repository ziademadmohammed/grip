package capture

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"grip/internal/database"
)

// ApplicationStats tracks statistics for a specific application
type ApplicationStats struct {
	ProcessID         uint32
	ProcessName       string
	ProcessPath       string
	TotalPackets      atomic.Uint64
	TotalBytes        atomic.Uint64
	PacketsByProtocol sync.Map // map[string]uint64
	Destinations      sync.Map // map[string]bool - set of IPs/domains
	LastSavedToDB     time.Time
}

// Statistics tracks overall system statistics and per-application statistics
type Statistics struct {
	StartTime         time.Time
	TotalPackets      atomic.Uint64
	TotalBytes        atomic.Uint64
	PacketsByProtocol sync.Map // map[string]uint64
	ApplicationStats  sync.Map // map[string]ApplicationStats - key is process name
	LastSavedToDB     time.Time
}

var stats Statistics
var statsMutex sync.RWMutex
var saveInterval = time.Minute / 2

func init() {
	stats = Statistics{
		StartTime:     time.Now(),
		LastSavedToDB: time.Now(),
	}

	// Start goroutine to periodically save stats to database
	go saveStatsPeriodically()
}

// incrementProtocolCount increments the count for a specific protocol
func incrementProtocolCount(protocol string) {
	value, _ := stats.PacketsByProtocol.LoadOrStore(protocol, uint64(0))
	stats.PacketsByProtocol.Store(protocol, value.(uint64)+1)
}

// GetStatistics returns a copy of the current statistics
func GetStatistics() Statistics {
	return stats
}

// updateStats updates the total packet and byte counts
func updateStats(bytes uint64) {
	stats.TotalPackets.Add(1)
	stats.TotalBytes.Add(bytes)
}

// updateAppStats updates statistics for a specific application
func updateAppStats(processID uint32, processName, processPath string,
	protocol string, bytes uint64, destination string) {
	if processName == "" {
		return // Skip unknown applications
	}

	// Use process name as key for the app stats
	key := processName

	// Get or create application stats
	appStatsObj, _ := stats.ApplicationStats.LoadOrStore(key, &ApplicationStats{
		ProcessID:     processID,
		ProcessName:   processName,
		ProcessPath:   processPath,
		LastSavedToDB: time.Now(),
	})

	appStats := appStatsObj.(*ApplicationStats)

	// Update app stats
	appStats.TotalPackets.Add(1)
	appStats.TotalBytes.Add(bytes)

	// Update protocol count for app
	protoValue, _ := appStats.PacketsByProtocol.LoadOrStore(protocol, uint64(0))
	appStats.PacketsByProtocol.Store(protocol, protoValue.(uint64)+1)

	// Add destination to set (use bool value since sync.Map doesn't have a Set type)
	if destination != "" {
		appStats.Destinations.Store(destination, true)
	}

	// Save to database if enough time has passed
	if time.Since(appStats.LastSavedToDB) > saveInterval {
		go saveAppStatsToDB(appStats)
		appStats.LastSavedToDB = time.Now()
	}
}

// GetApplicationStats returns a map of process names to their statistics
func GetApplicationStats() map[string]*ApplicationStats {
	result := make(map[string]*ApplicationStats)

	stats.ApplicationStats.Range(func(key, value interface{}) bool {
		result[key.(string)] = value.(*ApplicationStats)
		return true
	})

	return result
}

// GetDestinationsForApp returns all destinations for a specific application
func GetDestinationsForApp(processName string) []string {
	appStatsObj, ok := stats.ApplicationStats.Load(processName)
	if !ok {
		return []string{}
	}

	appStats := appStatsObj.(*ApplicationStats)
	destinations := []string{}

	appStats.Destinations.Range(func(key, value interface{}) bool {
		destinations = append(destinations, key.(string))
		return true
	})

	return destinations
}

// SaveAllStatsToDB saves all statistics to the database
func SaveAllStatsToDB() {
	LogInfo("Saving all application statistics to database...")

	// Count how many apps we're saving
	appCount := 0
	stats.ApplicationStats.Range(func(key, value interface{}) bool {
		appCount++
		return true
	})

	if appCount == 0 {
		LogInfo("No application statistics to save")
		return
	}

	LogDebug("Found %d applications with statistics to save", appCount)

	// Track success and failure counts
	successCount := 0
	failureCount := 0

	// For each application, save its stats
	stats.ApplicationStats.Range(func(key, value interface{}) bool {
		appName := key.(string)
		appStats := value.(*ApplicationStats)

		// Skip apps with no packets
		if appStats.TotalPackets.Load() == 0 {
			return true
		}

		// Try to save this app's stats
		err := func() error {
			defer func() {
				if r := recover(); r != nil {
					LogError("Panic while saving stats for %s: %v", appName, r)
				}
			}()

			saveAppStatsToDB(appStats)
			return nil
		}()

		if err != nil {
			failureCount++
		} else {
			successCount++
		}

		return true
	})

	stats.LastSavedToDB = time.Now()
	LogInfo("Statistics saved to database: %d successful, %d failed", successCount, failureCount)
}

// saveAppStatsToDB saves a single application's statistics to the database
func saveAppStatsToDB(appStats *ApplicationStats) {
	if appStats == nil {
		LogError("Cannot save nil application stats")
		return
	}

	// Skip if no packets were recorded for this app
	if appStats.TotalPackets.Load() == 0 {
		return
	}

	// Check if database is initialized
	if !database.IsInitialized() {
		LogError("Cannot save stats for %s: database not initialized", appStats.ProcessName)
		return
	}

	LogDebug("Saving stats for application: %s (PID: %d)", appStats.ProcessName, appStats.ProcessID)

	// Convert destinations map to JSON array
	destinations := []string{}
	appStats.Destinations.Range(func(key, value interface{}) bool {
		destinations = append(destinations, key.(string))
		return true
	})

	destinationsJSON, err := json.Marshal(destinations)
	if err != nil {
		LogError("Failed to marshal destinations to JSON: %v", err)
		return
	}

	// Create database stats object
	dbStats := &database.ApplicationStats{
		ProcessID:    appStats.ProcessID,
		ProcessName:  appStats.ProcessName,
		ProcessPath:  appStats.ProcessPath,
		TotalPackets: appStats.TotalPackets.Load(),
		TotalBytes:   appStats.TotalBytes.Load(),
		Destinations: string(destinationsJSON),
	}

	// Save to database
	if err := database.StoreAppStats(dbStats); err != nil {
		LogError("Failed to save application stats to database: %v", err)
		return
	}

	// Save protocol statistics
	appStats.PacketsByProtocol.Range(func(key, value interface{}) bool {
		protocol := key.(string)
		count := value.(uint64)

		if err := database.StoreProtocolStats(appStats.ProcessName, appStats.ProcessID, protocol, count); err != nil {
			LogError("Failed to save protocol stats for %s: %v", appStats.ProcessName, err)
		}

		return true
	})

	LogDebug("Successfully saved stats for application: %s", appStats.ProcessName)
}

// saveStatsPeriodically saves statistics to the database at regular intervals
func saveStatsPeriodically() {
	ticker := time.NewTicker(saveInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Check if we have any stats to save
		hasStats := false
		stats.ApplicationStats.Range(func(key, value interface{}) bool {
			hasStats = true
			return false // stop after first item
		})

		if hasStats {
			LogDebug("Periodic saving of statistics to database...")
			SaveAllStatsToDB()
		}
	}
}
