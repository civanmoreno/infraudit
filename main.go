package main

import (
	"github.com/civanmoreno/infraudit/cmd"

	// Register checks via init() — autodiscovery
	_ "github.com/civanmoreno/infraudit/internal/checks/auth"
	_ "github.com/civanmoreno/infraudit/internal/checks/backup"
	_ "github.com/civanmoreno/infraudit/internal/checks/boot"
	_ "github.com/civanmoreno/infraudit/internal/checks/container"
	_ "github.com/civanmoreno/infraudit/internal/checks/cron"
	_ "github.com/civanmoreno/infraudit/internal/checks/crypto"
	_ "github.com/civanmoreno/infraudit/internal/checks/filesystem"
	_ "github.com/civanmoreno/infraudit/internal/checks/hardening"
	_ "github.com/civanmoreno/infraudit/internal/checks/logging"
	_ "github.com/civanmoreno/infraudit/internal/checks/malware"
	_ "github.com/civanmoreno/infraudit/internal/checks/network"
	_ "github.com/civanmoreno/infraudit/internal/checks/nfs"
	_ "github.com/civanmoreno/infraudit/internal/checks/packages"
	_ "github.com/civanmoreno/infraudit/internal/checks/pam"
	_ "github.com/civanmoreno/infraudit/internal/checks/rlimit"
	_ "github.com/civanmoreno/infraudit/internal/checks/secrets"
	_ "github.com/civanmoreno/infraudit/internal/checks/services"
)

func main() {
	cmd.Execute()
}
