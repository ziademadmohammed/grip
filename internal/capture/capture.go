package capture

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"grip/internal/database"
	"grip/internal/process"
)

var (
	snapshot_len int32         = 1024
	promiscuous  bool          = true
	timeout      time.Duration = -1 * time.Second

	// Map to track device names to IDs
	deviceIDMap    = make(map[string]int64)
	deviceMapMutex sync.RWMutex

	// Process every 1000 packets
	packetCounter uint64
)

func checkNpcapInstallation() error {
	// Common paths where wpcap.dll might be located
	paths := []string{
		"C:\\Windows\\System32\\Npcap\\wpcap.dll",
		"C:\\Windows\\System32\\wpcap.dll",
		"C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll",
		"C:\\Windows\\SysWOW64\\wpcap.dll",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
	}

	return fmt.Errorf("Npcap/WinPcap not found. Please install Npcap from https://npcap.com/#download")
}

func StartCapture() error {
	// Initialize database
	if err := database.InitDatabase(); err != nil {
		return fmt.Errorf("failed to initialize database: %v", err)
	}

	// Check for Npcap installation
	if err := checkNpcapInstallation(); err != nil {
		return err
	}

	// Get a list of all network devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return fmt.Errorf("error finding network devices (make sure you're running as Administrator): %v", err)
	}

	if len(devices) == 0 {
		return fmt.Errorf("no network interfaces found")
	}

	LogDebug("Starting capture on %d network interfaces", len(devices))

	// Store network interfaces in database
	for _, device := range devices {
		iface := database.NetworkInterface{
			Name:        device.Name,
			Description: device.Description,
			CreatedAt:   time.Now(),
		}
		deviceID, err := database.StoreInterface(iface)
		if err != nil {
			LogDebug("Error storing interface %s: %v", device.Name, err)
		} else {
			// Store device ID in map
			deviceMapMutex.Lock()
			deviceIDMap[device.Name] = deviceID
			deviceMapMutex.Unlock()
		}
		LogInterface(device.Name, device.Description)
	}

	// Start capturing on each device in a separate goroutine
	for _, device := range devices {
		go captureDevice(device.Name)
	}

	return nil
}

func captureDevice(deviceName string) {
	handle, err := pcap.OpenLive(deviceName, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Printf("Error opening device %s: %v", deviceName, err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Log basic packet information
		processPacket(deviceName, packet)
	}
}

// Extract network information from a packet
func extractNetworkInfo(packet gopacket.Packet) (src, dst, srcPort, dstPort, protocol string, length int, valid bool) {
	// Get network layer info
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return "", "", "", "", "", 0, false
	}

	// Get transport layer info
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return "", "", "", "", "", 0, false
	}

	// Get source and destination IPs
	flow := networkLayer.NetworkFlow()
	src = flow.Src().String()
	dst = flow.Dst().String()

	// Get source and destination ports
	tflow := transportLayer.TransportFlow()
	srcPort = strings.TrimPrefix(tflow.Src().String(), ":")
	dstPort = strings.TrimPrefix(tflow.Dst().String(), ":")

	protocol = transportLayer.LayerType().String()
	length = len(packet.Data())

	return src, dst, srcPort, dstPort, protocol, length, true
}

// Look up process information based on network connection details
func lookupProcessInfo(protocol string, srcPortInt, dstPortInt uint16, direction string) (*process.ProcessInfo, error) {
	var (
		info *process.ProcessInfo
		err  error
	)

	// For TCP traffic
	if protocol == "TCP" && (direction == "outgoing" || direction == "internal") {
		// First check source port for outgoing or internal traffic
		info, err = process.FindTCPProcess(srcPortInt, dstPortInt, 0, 0)
		if err == nil {
			return info, nil
		}
		LogDebug("Source TCP lookup failed for outgoing traffic: %v", err)
	}

	if protocol == "TCP" && (direction == "incoming" || direction == "internal") {
		// Check destination port for incoming or internal traffic
		info, err = process.FindTCPProcess(dstPortInt, srcPortInt, 0, 0)
		if err == nil {
			return info, nil
		}
		LogDebug("Destination TCP lookup failed for incoming traffic: %v", err)
	}

	// For UDP traffic
	if protocol == "UDP" && (direction == "outgoing" || direction == "internal") {
		// First check source port for outgoing or internal traffic
		info, err = process.FindUDPProcess(srcPortInt, 0)
		if err == nil {
			return info, nil
		}
		LogDebug("Source UDP lookup failed for outgoing traffic: %v", err)
	}

	if protocol == "UDP" && (direction == "incoming" || direction == "internal") {
		// Check destination port for incoming traffic
		info, err = process.FindUDPProcess(dstPortInt, 0)
		if err == nil {
			return info, nil
		}
		LogDebug("Destination UDP lookup failed for incoming traffic: %v", err)
	}

	// If we reach here, all applicable checks failed
	LogError("Failed to find process for %s traffic (%s) between ports %d and %d",
		protocol, direction, srcPortInt, dstPortInt)
	return nil, fmt.Errorf("process not found")
}

// Create and store a packet record
func createAndStorePacket(deviceName, src, srcPort, dst, dstPort, protocol string, length int, direction string, processInfo *process.ProcessInfo) {
	// Get device ID from map
	deviceMapMutex.RLock()
	deviceID, exists := deviceIDMap[deviceName]
	deviceMapMutex.RUnlock()

	if !exists {
		LogError("No device ID found for device: %s", deviceName)
		return
	}

	// Create packet record
	record := database.PacketRecord{
		Timestamp: time.Now(),
		DeviceID:  deviceID, // Use device ID instead of name
		SrcIP:     src,
		SrcPort:   srcPort,
		DstIP:     dst,
		DstPort:   dstPort,
		Protocol:  protocol,
		Length:    length,
		Direction: direction,
	}

	if processInfo != nil {
		record.ProcessID = processInfo.ProcessID
		record.ProcessName = processInfo.ProcessName
		record.ProcessPath = processInfo.ExecutablePath

		// Update application-specific statistics
		destination := dst
		updateAppStats(
			processInfo.ProcessID,
			processInfo.ProcessName,
			processInfo.ExecutablePath,
			protocol,
			uint64(length),
			destination,
		)
	}

	// Store in database
	if err := database.StorePacket(record); err != nil {
		LogDebug("Error storing packet in database: %v", err)
	}

	// Log packet information (still use device name for logging)
	LogPacket(deviceName, src, srcPort, dst, dstPort, protocol, length, direction, processInfo)
}

func StopCapture() {
	// Save all statistics to database before shutdown
	SaveAllStatsToDB()

	// Close database and logger
	database.CloseDatabase()
	CloseLogger()
}

// Determine if an IP address is local to the machine
func isLocalIP(ip string) bool {
	// Check for loopback addresses
	if strings.HasPrefix(ip, "127.") || ip == "::1" {
		return true
	}

	// Get all interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}

	// Check all interfaces
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		// Check all addresses on this interface
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.String() == ip {
					return true
				}
			case *net.IPAddr:
				if v.IP.String() == ip {
					return true
				}
			}
		}
	}
	return false
}

// Determine packet direction based on source and destination IPs
func determinePacketDirection(srcIP, dstIP string) string {
	srcIsLocal := isLocalIP(srcIP)
	dstIsLocal := isLocalIP(dstIP)

	if srcIsLocal && dstIsLocal {
		return "internal" // Both IPs are local - internal traffic
	} else if srcIsLocal && !dstIsLocal {
		return "outgoing" // Source is local, destination is not - outgoing traffic
	} else if !srcIsLocal && dstIsLocal {
		return "incoming" // Source is not local, destination is - incoming traffic
	} else {
		return "external" // Neither source nor destination is local - external traffic passing through
	}
}

func processPacket(deviceName string, packet gopacket.Packet) {
	// Extract network information
	src, dst, srcPort, dstPort, protocol, length, valid := extractNetworkInfo(packet)
	if !valid {
		return
	}

	// Update statistics
	updateStats(uint64(length))
	incrementProtocolCount(protocol)

	// Increment packet counter
	newCount := atomic.AddUint64(&packetCounter, 1)

	// Every 1000 packets, save stats
	if newCount%1000 == 0 {
		LogDebug("Processing packet #%d, triggering stats save", newCount)
		go SaveAllStatsToDB()
	}

	// Parse port strings to integers for process lookup
	srcPortInt := uint16(0)
	dstPortInt := uint16(0)
	if sp, err := strconv.ParseUint(srcPort, 10, 16); err == nil {
		srcPortInt = uint16(sp)
	}
	if dp, err := strconv.ParseUint(dstPort, 10, 16); err == nil {
		dstPortInt = uint16(dp)
	}

	// Determine packet direction
	direction := determinePacketDirection(src, dst)

	// Look up process information
	processInfo, err := lookupProcessInfo(protocol, srcPortInt, dstPortInt, direction)
	if err != nil {
		LogError("Process lookup failed for %s:%s -> %s:%s (%s): %v",
			src, srcPort, dst, dstPort, protocol, err)
	}

	// Create and store packet record
	createAndStorePacket(deviceName, src, srcPort, dst, dstPort, protocol, length, direction, processInfo)
}
