package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

type NetworkInterface struct {
	ID          int64
	Name        string
	Description string
	CreatedAt   time.Time
}

type PacketRecord struct {
	ID          int64
	Timestamp   time.Time
	DeviceID    int64
	SrcIP       string
	SrcPort     string
	DstIP       string
	DstPort     string
	Protocol    string
	Length      int
	ProcessID   uint32
	ProcessName string
	ProcessPath string
	Direction   string // "incoming", "outgoing", "internal", or "external"
}

// ApplicationStats represents statistics for a specific application
type ApplicationStats struct {
	ID           int64
	ProcessID    uint32
	ProcessName  string
	ProcessPath  string
	TotalPackets uint64
	TotalBytes   uint64
	LastUpdated  time.Time
	Destinations string // JSON array of destinations
	FirstSeen    time.Time
	LastSeen     time.Time
}

func getDefaultDBPath() (string, error) {
	appData := os.Getenv("LOCALAPPDATA")
	if appData == "" {
		return "", fmt.Errorf("LOCALAPPDATA environment variable not set")
	}

	dbDir := filepath.Join(appData, "GripNetMonitor")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create database directory: %v", err)
	}

	return filepath.Join(dbDir, "netmonitor.db"), nil
}

func InitDatabase() error {
	dbPath, err := getDefaultDBPath()
	if err != nil {
		return fmt.Errorf("failed to get database path: %v", err)
	}

	db, err = sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	// Set pragmas for better performance
	if _, err := db.Exec(`PRAGMA synchronous = NORMAL`); err != nil {
		return fmt.Errorf("error setting synchronous pragma: %v", err)
	}
	if _, err := db.Exec(`PRAGMA cache_size = -2000`); err != nil {
		return fmt.Errorf("error setting cache size: %v", err)
	}

	// Create tables if they don't exist
	if err := createTables(); err != nil {
		return fmt.Errorf("error creating tables: %v", err)
	}

	// Perform database migrations if needed
	if err := migrateDatabase(); err != nil {
		return fmt.Errorf("error migrating database: %v", err)
	}

	log.Printf("Database initialized at: %s", dbPath)
	return nil
}

func createTables() error {
	// Create network_interfaces table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS network_interfaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(name, description)
		)
	`)
	if err != nil {
		return err
	}

	// Create packet_logs table with indexes
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS packet_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			device_id INTEGER NOT NULL, 
			src_ip TEXT NOT NULL,
			src_port TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			dst_port TEXT NOT NULL,
			protocol TEXT NOT NULL,
			length INTEGER NOT NULL,
			process_id INTEGER,
			process_name TEXT,
			process_path TEXT,
			direction TEXT,
			FOREIGN KEY (device_id) REFERENCES network_interfaces (id)
		)
	`)
	if err != nil {
		return err
	}

	// Create indexes in separate statements for better error handling
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_timestamp ON packet_logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_protocol ON packet_logs(protocol)`,
		`CREATE INDEX IF NOT EXISTS idx_process_name ON packet_logs(process_name)`,
		`CREATE INDEX IF NOT EXISTS idx_device_id ON packet_logs(device_id)`,
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("error creating index: %v", err)
		}
	}

	// Create application statistics tables
	if err := createAppStatsTables(); err != nil {
		return fmt.Errorf("error creating application stats tables: %v", err)
	}

	return nil
}

func migrateDatabase() error {
	// Check if direction column exists
	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('packet_logs') 
		WHERE name = 'direction'
	`).Scan(&count)

	if err != nil {
		return fmt.Errorf("error checking for direction column: %v", err)
	}

	// Add the direction column if it doesn't exist
	if count == 0 {
		log.Printf("Adding direction column to packet_logs table")
		_, err := db.Exec(`ALTER TABLE packet_logs ADD COLUMN direction TEXT`)
		if err != nil {
			return fmt.Errorf("error adding direction column: %v", err)
		}
	}

	// Check if we need to migrate from device to device_id
	err = db.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('packet_logs') 
		WHERE name = 'device'
	`).Scan(&count)

	if err != nil {
		return fmt.Errorf("error checking for device column: %v", err)
	}

	// If device column exists, we need to migrate to device_id
	if count > 0 {
		log.Printf("Migrating from device to device_id in packet_logs table")

		// First, add the device_id column if it doesn't exist
		_, err = db.Exec(`ALTER TABLE packet_logs ADD COLUMN device_id INTEGER`)
		if err != nil {
			return fmt.Errorf("error adding device_id column: %v", err)
		}

		// Create a temporary table for migration
		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS packet_logs_new (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				device_id INTEGER NOT NULL,
				src_ip TEXT NOT NULL,
				src_port TEXT NOT NULL,
				dst_ip TEXT NOT NULL,
				dst_port TEXT NOT NULL,
				protocol TEXT NOT NULL,
				length INTEGER NOT NULL,
				process_id INTEGER,
				process_name TEXT,
				process_path TEXT,
				direction TEXT,
				FOREIGN KEY (device_id) REFERENCES network_interfaces (id)
			)
		`)
		if err != nil {
			return fmt.Errorf("error creating new packet_logs table: %v", err)
		}

		// Move data to the new table, ignoring records that can't be migrated
		_, err = db.Exec(`
			INSERT INTO packet_logs_new (
				timestamp, device_id, src_ip, src_port, dst_ip, dst_port,
				protocol, length, process_id, process_name, process_path, direction
			)
			SELECT 
				p.timestamp, 
				COALESCE(n.id, 0) AS device_id, 
				p.src_ip, p.src_port, p.dst_ip, p.dst_port,
				p.protocol, p.length, p.process_id, p.process_name, p.process_path, p.direction
			FROM packet_logs p
			LEFT JOIN network_interfaces n ON p.device = n.name
		`)
		if err != nil {
			return fmt.Errorf("error migrating data to new table: %v", err)
		}

		// Replace old table with new one
		_, err = db.Exec(`DROP TABLE packet_logs`)
		if err != nil {
			return fmt.Errorf("error dropping old table: %v", err)
		}

		_, err = db.Exec(`ALTER TABLE packet_logs_new RENAME TO packet_logs`)
		if err != nil {
			return fmt.Errorf("error renaming new table: %v", err)
		}

		// Recreate indexes
		indexes := []string{
			`CREATE INDEX IF NOT EXISTS idx_timestamp ON packet_logs(timestamp)`,
			`CREATE INDEX IF NOT EXISTS idx_protocol ON packet_logs(protocol)`,
			`CREATE INDEX IF NOT EXISTS idx_process_name ON packet_logs(process_name)`,
			`CREATE INDEX IF NOT EXISTS idx_device_id ON packet_logs(device_id)`,
		}

		for _, idx := range indexes {
			if _, err := db.Exec(idx); err != nil {
				return fmt.Errorf("error recreating index: %v", err)
			}
		}

		log.Printf("Migration from device to device_id completed")
	}

	return nil
}

func StoreInterface(iface NetworkInterface) (int64, error) {
	// Check if interface already exists
	var exists bool
	var id int64
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM network_interfaces 
			WHERE name = ? AND description = ?
		)
	`, iface.Name, iface.Description).Scan(&exists)

	if err != nil {
		return 0, fmt.Errorf("error checking interface existence: %v", err)
	}

	if exists {
		// Get the ID of the existing interface
		err = db.QueryRow(`
			SELECT id FROM network_interfaces
			WHERE name = ? AND description = ?
		`, iface.Name, iface.Description).Scan(&id)
		if err != nil {
			return 0, fmt.Errorf("error getting interface ID: %v", err)
		}
		log.Printf("Interface already exists: %s (%s), ID: %d", iface.Name, iface.Description, id)
		return id, nil
	}

	// Insert new interface
	result, err := db.Exec(`
		INSERT INTO network_interfaces (name, description)
		VALUES (?, ?)
	`, iface.Name, iface.Description)

	if err != nil {
		return 0, fmt.Errorf("error storing interface: %v", err)
	}

	// Get the ID of the inserted interface
	id, err = result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("error getting last insert ID: %v", err)
	}

	log.Printf("Added new interface: %s (%s), ID: %d", iface.Name, iface.Description, id)
	return id, nil
}

func StorePacket(packet PacketRecord) error {
	_, err := db.Exec(`
		INSERT INTO packet_logs (
			timestamp, device_id, src_ip, src_port, dst_ip, dst_port,
			protocol, length, process_id, process_name, process_path, direction
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		packet.Timestamp,
		packet.DeviceID,
		packet.SrcIP,
		packet.SrcPort,
		packet.DstIP,
		packet.DstPort,
		packet.Protocol,
		packet.Length,
		sql.NullInt32{Int32: int32(packet.ProcessID), Valid: packet.ProcessID > 0},
		sql.NullString{String: packet.ProcessName, Valid: packet.ProcessName != ""},
		sql.NullString{String: packet.ProcessPath, Valid: packet.ProcessPath != ""},
		sql.NullString{String: packet.Direction, Valid: packet.Direction != ""},
	)

	if err != nil {
		log.Printf("Error storing packet: %v", err)
	}
	return err
}

func CloseDatabase() {
	if db != nil {
		db.Close()
	}
}

// Initialize application statistics tables
func createAppStatsTables() error {
	// Create application_stats table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS application_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			process_id INTEGER NOT NULL,
			process_name TEXT NOT NULL,
			process_path TEXT,
			total_packets INTEGER NOT NULL DEFAULT 0,
			total_bytes INTEGER NOT NULL DEFAULT 0,
			last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			destinations TEXT, -- JSON array
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(process_name, process_id)
		)
	`)
	if err != nil {
		return err
	}

	// Create protocol_stats table for per-application protocol statistics
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS protocol_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_stats_id INTEGER NOT NULL,
			protocol TEXT NOT NULL,
			packet_count INTEGER NOT NULL DEFAULT 0,
			UNIQUE(app_stats_id, protocol),
			FOREIGN KEY (app_stats_id) REFERENCES application_stats(id)
		)
	`)
	if err != nil {
		return err
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_app_stats_process_name ON application_stats(process_name)`,
		`CREATE INDEX IF NOT EXISTS idx_app_stats_process_id ON application_stats(process_id)`,
		`CREATE INDEX IF NOT EXISTS idx_protocol_stats_app_id ON protocol_stats(app_stats_id)`,
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("error creating index: %v", err)
		}
	}

	return nil
}

// IsInitialized returns whether the database is initialized
func IsInitialized() bool {
	return db != nil
}

// StoreAppStats stores or updates application statistics in the database
func StoreAppStats(stats *ApplicationStats) error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	// First try to update existing record
	result, err := db.Exec(`
		UPDATE application_stats SET
			total_packets = ?,
			total_bytes = ?,
			last_updated = ?,
			destinations = ?,
			last_seen = ?,
			process_path = COALESCE(?, process_path)
		WHERE process_name = ? AND process_id = ?
	`,
		stats.TotalPackets,
		stats.TotalBytes,
		time.Now(),
		stats.Destinations,
		time.Now(),
		stats.ProcessPath,
		stats.ProcessName,
		stats.ProcessID,
	)
	if err != nil {
		return fmt.Errorf("failed to update app stats: %v", err)
	}

	// Check if the update affected any rows
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %v", err)
	}

	// If no rows were updated, insert a new record
	if rowsAffected == 0 {
		result, err = db.Exec(`
			INSERT INTO application_stats (
				process_id, process_name, process_path, 
				total_packets, total_bytes, 
				last_updated, destinations, 
				first_seen, last_seen
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			stats.ProcessID,
			stats.ProcessName,
			stats.ProcessPath,
			stats.TotalPackets,
			stats.TotalBytes,
			time.Now(),
			stats.Destinations,
			time.Now(),
			time.Now(),
		)
		if err != nil {
			return fmt.Errorf("failed to insert app stats: %v", err)
		}
	}

	return nil
}

// StoreProtocolStats stores protocol statistics for an application
func StoreProtocolStats(appName string, processID uint32, protocol string, packetCount uint64) error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	// First get the app_stats_id
	var appStatsID int64
	err := db.QueryRow(`
		SELECT id FROM application_stats 
		WHERE process_name = ? AND process_id = ?
	`, appName, processID).Scan(&appStatsID)

	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("application stats not found for %s (PID %d)", appName, processID)
		}
		return fmt.Errorf("error getting app stats ID: %v", err)
	}

	// Now update the protocol stats
	_, err = db.Exec(`
		INSERT INTO protocol_stats (app_stats_id, protocol, packet_count)
		VALUES (?, ?, ?)
		ON CONFLICT (app_stats_id, protocol) 
		DO UPDATE SET packet_count = ?
	`, appStatsID, protocol, packetCount, packetCount)

	if err != nil {
		return fmt.Errorf("failed to update protocol stats: %v", err)
	}

	return nil
}
