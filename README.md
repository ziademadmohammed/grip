# GripNetMonitor

A real-time network traffic monitoring tool for Windows that captures, analyzes, and logs network packets with process information.

## Features

- Real-time packet capture and analysis
- Process identification for network connections
- Traffic direction classification (incoming, outgoing, internal, external)
- Persistent storage in SQLite database
- Windows service support
- Statistical reporting

## Requirements

### System Requirements

- Windows 10/11 or Windows Server 2016+
- Administrator privileges (required for packet capture and process lookup)

### Dependencies

- [Npcap](https://npcap.com/#download) - Packet capture library for Windows
- [Go](https://golang.org/dl/) - Go programming language (1.19+ recommended)
- GCC compiler for CGO support (needed for SQLite)
  - [MinGW-w64](https://www.mingw-w64.org/downloads/) or
  - [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or
  - [MSYS2](https://www.msys2.org/)

## Installation

### Quick Install

1. Download the latest release from the [Releases](https://github.com/yourusername/grip/releases) page
2. Install [Npcap](https://npcap.com/#download) if not already installed
3. Run the application as Administrator

### Building from Source

1. Install the required dependencies:
   - Go 1.19+
   - Npcap
   - GCC compiler (MinGW-w64, TDM-GCC, or MSYS2)

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/grip.git
   cd grip
   ```

3. Install Go dependencies:
   ```bash
   go mod download
   ```

4. Build the application:
   ```bash
   # Using make (recommended)
   make build
   
   # Or using Go directly (requires CGO_ENABLED=1)
   set CGO_ENABLED=1
   go build -o build/netmonitor.exe cmd/netmonitor/main.go
   ```

## Usage

### Running in Debug Mode

```bash
# Using the executable directly
build\netmonitor.exe debug

# Using make
make run-debug
```

### Windows Service Management

```bash
# Install the service
build\netmonitor.exe install
# or: make install-service

# Start the service
net start NetMonitor
# or: make start-service

# Stop the service
net stop NetMonitor
# or: make stop-service

# Remove the service
build\netmonitor.exe remove
# or: make remove-service
```

## Configuration

GripNetMonitor can be configured using command-line flags:

```bash
# Enable/disable packet logging (default: false)
build\netmonitor.exe debug -packet-logs=true

# Enable/disable interface logging (default: false)
build\netmonitor.exe debug -interface-logs=true

# Enable/disable debug logging (default: true)
build\netmonitor.exe debug -debug-logs=true
```

## Data Storage

Network packet data is stored in a SQLite database located at:
```
%LOCALAPPDATA%\GripNetMonitor\netmonitor.db
```

### Database Schema

The database contains the following tables:

#### network_interfaces
- `id`: Auto-incremented primary key
- `name`: Interface name
- `description`: Interface description
- `created_at`: Creation timestamp

#### packet_logs
- `id`: Auto-incremented primary key
- `timestamp`: Packet capture time
- `device`: Capturing device name
- `src_ip`: Source IP address
- `src_port`: Source port
- `dst_ip`: Destination IP address
- `dst_port`: Destination port
- `protocol`: Network protocol (TCP, UDP, etc.)
- `length`: Packet length in bytes
- `process_id`: Process ID (if available)
- `process_name`: Process name (if available)
- `process_path`: Process executable path (if available)
- `direction`: Packet direction (incoming, outgoing, internal, external)

## Packet Direction Classification

Packets are classified into four categories:

- **Incoming**: Traffic from external sources to your machine
- **Outgoing**: Traffic from your machine to external destinations
- **Internal**: Traffic between local addresses on your machine
- **External**: Traffic passing through that isn't to or from your machine

## Troubleshooting

### Common Issues

#### "wpcap.dll not found" or "Error finding network devices"
- Ensure Npcap is installed properly
- Try reinstalling Npcap with the "WinPcap API-compatible Mode" option enabled

#### "Administrator privileges required"
- Run the application as Administrator
- For the service, ensure it's configured to run with Administrator privileges

#### Process information not available
- Ensure the application is running with Administrator privileges
- Some system processes may not be identifiable

## License

[MIT License](LICENSE)

## Acknowledgments

- [gopacket](https://github.com/google/gopacket) - Packet processing library
- [Npcap](https://npcap.com) - Windows packet capture library
- [go-sqlite3](https://github.com/mattn/go-sqlite3) - SQLite driver for Go 