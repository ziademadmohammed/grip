package capture

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIPHlpAPI             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIPHlpAPI.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIPHlpAPI.NewProc("GetExtendedUdpTable")

	// Cache for admin check to avoid repeated checks
	adminCheckOnce sync.Once
	isAdminProcess bool
	adminCheckErr  error
)

type ProcessInfo struct {
	ProcessID      uint32
	ProcessName    string
	ExecutablePath string
}

type TCPRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	ProcessID  uint32
}

type UDPRow struct {
	LocalAddr uint32
	LocalPort uint32
	ProcessID uint32
}

func getProcessDetails(pid uint32) (*ProcessInfo, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(handle)

	var path [windows.MAX_PATH]uint16
	length := uint32(len(path))
	if err := windows.QueryFullProcessImageName(handle, 0, &path[0], &length); err != nil {
		return nil, fmt.Errorf("QueryFullProcessImageName failed: %v", err)
	}

	info := &ProcessInfo{
		ProcessID:      pid,
		ExecutablePath: windows.UTF16ToString(path[:length]),
		ProcessName:    windows.UTF16ToString(path[windows.MAX_PATH-length:]),
	}

	return info, nil
}

func findTCPProcess(localPort uint16, remotePort uint16, localAddr, remoteAddr uint32) (*ProcessInfo, error) {
	// Check if running as administrator
	isAdmin, err := isRunningAsAdmin()
	if err != nil {
		return nil, fmt.Errorf("failed to check admin status: %v", err)
	}

	if !isAdmin {
		return nil, fmt.Errorf("administrator privileges required for process lookups")
	}

	var size uint32 = 8192 // Start with a reasonable buffer size
	var table []byte
	var lastErr error

	// Try multiple times with increasing buffer sizes
	for attempts := 0; attempts < 3; attempts++ {
		table = make([]byte, size)

		ret, _, errCall := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&table[0])),
			uintptr(unsafe.Pointer(&size)),
			1, // Sort by PID
			0, // AF_INET
			5, // TCP_TABLE_OWNER_PID_ALL
			0,
		)

		// Windows ERROR_INSUFFICIENT_BUFFER is 122
		if ret == 122 {
			// Double the buffer size and try again
			size *= 2
			continue
		} else if ret != 0 {
			lastErr = fmt.Errorf("GetExtendedTcpTable failed with code %d: %v", ret, errCall)
			continue
		}

		// Success - process the data
		// Check if we have enough data for at least the count
		if len(table) < 4 {
			return nil, fmt.Errorf("TCP table data too small")
		}

		count := *(*uint32)(unsafe.Pointer(&table[0]))
		if count == 0 {
			return nil, fmt.Errorf("no TCP connections found")
		}

		rowSize := unsafe.Sizeof(TCPRow{})
		// Make sure we have enough data for the rows
		expectedSize := 4 + (uint32(rowSize) * count)
		if uint32(len(table)) < expectedSize {
			return nil, fmt.Errorf("TCP table data incomplete")
		}

		// Convert ports from host to network byte order for comparison
		localPortN := (localPort << 8) | (localPort >> 8)
		remotePortN := (remotePort << 8) | (remotePort >> 8)

		// Process the table data
		rows := (*[1024]TCPRow)(unsafe.Pointer(&table[4]))[:count:count]

		for i := uint32(0); i < count; i++ {
			row := rows[i]

			LogDebug("TCP Connection - Local: %d, Remote: %d, PID: %d",
				row.LocalPort, row.RemotePort, row.ProcessID)

			if row.LocalPort == uint32(localPortN) &&
				(remotePort == 0 || row.RemotePort == uint32(remotePortN)) &&
				(localAddr == 0 || row.LocalAddr == localAddr) &&
				(remoteAddr == 0 || row.RemoteAddr == remoteAddr) {
				return getProcessDetails(row.ProcessID)
			}
		}

		// If we get here, we processed the table but found no match
		return nil, fmt.Errorf("matching process not found for ports %d->%d", localPort, remotePort)
	}

	// If we get here, all attempts failed
	return nil, lastErr
}

// isRunningAsAdmin checks if the process has administrator privileges
// This is now cached after the first call
func isRunningAsAdmin() (bool, error) {
	// Only perform the check once and cache the result
	adminCheckOnce.Do(func() {
		var sid *windows.SID

		// Create a SID for the administrators group
		err := windows.AllocateAndInitializeSid(
			&windows.SECURITY_NT_AUTHORITY,
			2,
			windows.SECURITY_BUILTIN_DOMAIN_RID,
			windows.DOMAIN_ALIAS_RID_ADMINS,
			0, 0, 0, 0, 0, 0,
			&sid)
		if err != nil {
			adminCheckErr = err
			return
		}
		defer windows.FreeSid(sid)

		// Check if the current process token is a member of that SID
		token := windows.Token(0)
		member, err := token.IsMember(sid)
		if err != nil {
			adminCheckErr = err
			return
		}

		isAdminProcess = member
		LogDebug("Admin privileges check: %v", isAdminProcess)
	})

	return isAdminProcess, adminCheckErr
}

func findUDPProcess(localPort uint16, localAddr uint32) (*ProcessInfo, error) {
	// Check if running as administrator
	isAdmin, err := isRunningAsAdmin()
	if err != nil {
		return nil, fmt.Errorf("failed to check admin status: %v", err)
	}

	if !isAdmin {
		return nil, fmt.Errorf("administrator privileges required for process lookups")
	}

	var size uint32 = 8192 // Start with a reasonable buffer size
	var table []byte
	var lastErr error

	// Try multiple times with increasing buffer sizes
	for attempts := 0; attempts < 3; attempts++ {
		table = make([]byte, size)

		ret, _, errCall := procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&table[0])),
			uintptr(unsafe.Pointer(&size)),
			1, // Sort by PID
			0, // AF_INET
			1, // UDP_TABLE_OWNER_PID
			0,
		)

		// Windows ERROR_INSUFFICIENT_BUFFER is 122
		if ret == 122 {
			// Double the buffer size and try again
			size *= 2
			continue
		} else if ret != 0 {
			lastErr = fmt.Errorf("GetExtendedUdpTable failed with code %d: %v", ret, errCall)
			continue
		}

		// Success - process the data
		// Check if we have enough data for at least the count
		if len(table) < 4 {
			return nil, fmt.Errorf("UDP table data too small")
		}

		count := *(*uint32)(unsafe.Pointer(&table[0]))
		if count == 0 {
			return nil, fmt.Errorf("no UDP connections found")
		}

		rowSize := unsafe.Sizeof(UDPRow{})
		// Make sure we have enough data for the rows
		expectedSize := 4 + (uint32(rowSize) * count)
		if uint32(len(table)) < expectedSize {
			return nil, fmt.Errorf("UDP table data incomplete")
		}

		// Convert port from host to network byte order for comparison
		localPortN := (localPort << 8) | (localPort >> 8)

		// Process the table data
		rows := (*[1024]UDPRow)(unsafe.Pointer(&table[4]))[:count:count]

		for i := uint32(0); i < count; i++ {
			row := rows[i]

			LogDebug("UDP Connection - Local: %d, PID: %d",
				row.LocalPort, row.ProcessID)

			if row.LocalPort == uint32(localPortN) &&
				(localAddr == 0 || row.LocalAddr == localAddr) {
				return getProcessDetails(row.ProcessID)
			}
		}

		// If we get here, we processed the table but found no match
		return nil, fmt.Errorf("matching process not found for port %d", localPort)
	}

	// If we get here, all attempts failed
	return nil, lastErr
}
