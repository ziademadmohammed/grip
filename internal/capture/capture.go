package capture

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32         = 1024
	promiscuous  bool          = true
	timeout      time.Duration = -1 * time.Second
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
	// Check admin privileges first
	isAdmin, err := isRunningAsAdmin()
	if err != nil {
		return fmt.Errorf("failed to check administrator privileges: %v", err)
	}

	if !isAdmin {
		LogDebug("ADMINISTRATOR PRIVILEGES REQUIRED: This application requires administrator privileges to function properly. Please run as administrator.")
	}

	// Initialize database
	if err := InitDatabase(); err != nil {
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
		iface := NetworkInterface{
			Name:        device.Name,
			Description: device.Description,
			CreatedAt:   time.Now(),
		}
		if err := storeInterface(iface); err != nil {
			LogDebug("Error storing interface %s: %v", device.Name, err)
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
func lookupProcessInfo(protocol string, srcPortInt, dstPortInt uint16) (*ProcessInfo, error) {
	// Check for admin requirement first
	isAdmin, err := isRunningAsAdmin()
	if err != nil {
		return nil, fmt.Errorf("failed to check admin status: %v", err)
	}

	if !isAdmin {
		return nil, fmt.Errorf("administrator privileges required for process lookups")
	}

	// We have admin rights, attempt process lookups
	if protocol == "TCP" {
		if info, err := findTCPProcess(srcPortInt, dstPortInt, 0, 0); err == nil {
			return info, nil
		} else {
			initialErr := fmt.Errorf("source TCP lookup failed: %v", err)
			LogDebug("Source TCP lookup failed: %v", err)

			if info, err := findTCPProcess(dstPortInt, srcPortInt, 0, 0); err == nil {
				return info, nil
			} else {
				LogDebug("Destination TCP lookup also failed: %v", err)
				return nil, fmt.Errorf("both TCP lookups failed - source: %v, destination: %v", initialErr, err)
			}
		}
	} else if protocol == "UDP" {
		if info, err := findUDPProcess(srcPortInt, 0); err == nil {
			return info, nil
		} else {
			initialErr := fmt.Errorf("source UDP lookup failed: %v", err)
			LogDebug("Source UDP lookup failed: %v", err)

			if info, err := findUDPProcess(dstPortInt, 0); err == nil {
				return info, nil
			} else {
				LogDebug("Destination UDP lookup also failed: %v", err)
				return nil, fmt.Errorf("both UDP lookups failed - source: %v, destination: %v", initialErr, err)
			}
		}
	}

	return nil, fmt.Errorf("unsupported protocol: %s", protocol)
}

// Create and store a packet record
func createAndStorePacket(deviceName, src, srcPort, dst, dstPort, protocol string, length int, processInfo *ProcessInfo) {
	// Determine packet direction
	direction := determinePacketDirection(src, dst)

	// Create packet record
	record := PacketRecord{
		Timestamp: time.Now(),
		Device:    deviceName,
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
	}

	// Store in database
	if err := storePacket(record); err != nil {
		LogDebug("Error storing packet in database: %v", err)
	}

	// Log packet information
	LogPacket(deviceName, src, srcPort, dst, dstPort, protocol, length, direction, processInfo)
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

	// Parse port strings to integers for process lookup
	srcPortInt := uint16(0)
	dstPortInt := uint16(0)
	if sp, err := strconv.ParseUint(srcPort, 10, 16); err == nil {
		srcPortInt = uint16(sp)
	}
	if dp, err := strconv.ParseUint(dstPort, 10, 16); err == nil {
		dstPortInt = uint16(dp)
	}

	// Look up process information
	processInfo, err := lookupProcessInfo(protocol, srcPortInt, dstPortInt)
	if err != nil {
		LogDebug("Process lookup failed for %s:%s -> %s:%s (%s): %v",
			src, srcPort, dst, dstPort, protocol, err)
	}

	// Create and store packet record
	createAndStorePacket(deviceName, src, srcPort, dst, dstPort, protocol, length, processInfo)
}

func StopCapture() {
	closeDatabase()
	closeLogger()
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
