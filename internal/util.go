package util

import (
	"sync"

	"golang.org/x/sys/windows"
)

var (
	// Cache for admin check to avoid repeated checks
	adminCheckOnce sync.Once
	isAdminProcess bool
	adminCheckErr  error
)


// IsRunningAsAdmin checks if the process has administrator privileges
// This is now cached after the first call
func IsRunningAsAdmin() (bool, error) {
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
	})

	return isAdminProcess, adminCheckErr
}