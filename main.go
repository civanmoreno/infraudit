package main

import (
	"github.com/ivan/infraudit/cmd"

	// Register checks via init() — autodiscovery
	_ "github.com/ivan/infraudit/internal/checks/auth"
	_ "github.com/ivan/infraudit/internal/checks/backup"
	_ "github.com/ivan/infraudit/internal/checks/boot"
	_ "github.com/ivan/infraudit/internal/checks/container"
	_ "github.com/ivan/infraudit/internal/checks/cron"
	_ "github.com/ivan/infraudit/internal/checks/crypto"
	_ "github.com/ivan/infraudit/internal/checks/filesystem"
	_ "github.com/ivan/infraudit/internal/checks/hardening"
	_ "github.com/ivan/infraudit/internal/checks/logging"
	_ "github.com/ivan/infraudit/internal/checks/malware"
	_ "github.com/ivan/infraudit/internal/checks/network"
	_ "github.com/ivan/infraudit/internal/checks/nfs"
	_ "github.com/ivan/infraudit/internal/checks/packages"
	_ "github.com/ivan/infraudit/internal/checks/pam"
	_ "github.com/ivan/infraudit/internal/checks/rlimit"
	_ "github.com/ivan/infraudit/internal/checks/secrets"
	_ "github.com/ivan/infraudit/internal/checks/services"
)

func main() {
	cmd.Execute()
}
