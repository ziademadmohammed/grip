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
	Device      string
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
			device TEXT NOT NULL,
			src_ip TEXT NOT NULL,
			src_port TEXT NOT NULL,
			dst_ip TEXT NOT NULL,
			dst_port TEXT NOT NULL,
			protocol TEXT NOT NULL,
			length INTEGER NOT NULL,
			process_id INTEGER,
			process_name TEXT,
			process_path TEXT,
			direction TEXT
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
	}

	for _, idx := range indexes {
		if _, err := db.Exec(idx); err != nil {
			return fmt.Errorf("error creating index: %v", err)
		}
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

	return nil
}

func StoreInterface(iface NetworkInterface) error {
	// Check if interface already exists
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM network_interfaces 
			WHERE name = ? AND description = ?
		)
	`, iface.Name, iface.Description).Scan(&exists)

	if err != nil {
		return fmt.Errorf("error checking interface existence: %v", err)
	}

	if exists {
		log.Printf("Interface already exists: %s (%s)", iface.Name, iface.Description)
		return nil
	}

	// Insert new interface
	_, err = db.Exec(`
		INSERT INTO network_interfaces (name, description)
		VALUES (?, ?)
	`, iface.Name, iface.Description)

	if err != nil {
		return fmt.Errorf("error storing interface: %v", err)
	}

	log.Printf("Added new interface: %s (%s)", iface.Name, iface.Description)
	return nil
}

func StorePacket(packet PacketRecord) error {
	_, err := db.Exec(`
		INSERT INTO packet_logs (
			timestamp, device, src_ip, src_port, dst_ip, dst_port,
			protocol, length, process_id, process_name, process_path, direction
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		packet.Timestamp,
		packet.Device,
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
