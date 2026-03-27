package osinfo

import (
	"bufio"
	"os"
	"runtime"
	"strings"
	"sync"
)

// Family represents a Linux distribution family.
type Family string

const (
	Debian  Family = "debian"
	RedHat  Family = "redhat"
	SUSE    Family = "suse"
	Alpine  Family = "alpine"
	Arch    Family = "arch"
	Unknown Family = "unknown"
)

// PkgManager represents the system package manager.
type PkgManager string

const (
	Apt    PkgManager = "apt"
	Yum    PkgManager = "yum"
	Dnf    PkgManager = "dnf"
	Apk    PkgManager = "apk"
	Zypper PkgManager = "zypper"
	Pacman PkgManager = "pacman"
	NoPkg  PkgManager = "unknown"
)

// InitSystem represents the system init manager.
type InitSystem string

const (
	Systemd  InitSystem = "systemd"
	OpenRC   InitSystem = "openrc"
	SysVInit InitSystem = "sysvinit"
	NoInit   InitSystem = "unknown"
)

// Info holds the detected operating system information.
type Info struct {
	ID         string     // e.g. "ubuntu", "debian", "rhel", "centos", "alpine"
	Name       string     // e.g. "Ubuntu", "Debian GNU/Linux", "Alpine Linux"
	Version    string     // e.g. "24.04", "9", "3.21"
	VersionID  string     // e.g. "24.04", "9.3"
	Family     Family     // distribution family
	PkgManager PkgManager // detected package manager
	InitSystem InitSystem // detected init system
	Arch       string     // runtime.GOARCH
	PrettyName string     // human-readable name from os-release
	IDLike     []string   // parent distros (e.g. ["debian"] for ubuntu)
}

// osReleasePath can be overridden in tests.
var osReleasePath = "/etc/os-release"

var (
	once     sync.Once
	detected Info
)

// Detect returns the detected OS information.
// Results are cached after the first call.
func Detect() Info {
	once.Do(func() {
		detected = detect()
	})
	return detected
}

// Reset clears the cached detection. Used only in tests.
func Reset() {
	once = sync.Once{}
	detected = Info{}
}

func detect() Info {
	info := Info{
		Arch:   runtime.GOARCH,
		Family: Unknown,
	}

	fields := parseOSRelease(osReleasePath)
	if len(fields) == 0 {
		// Fallback: try /etc/os-release alternatives
		fields = parseOSRelease("/usr/lib/os-release")
	}

	info.ID = fields["ID"]
	info.Name = fields["NAME"]
	info.Version = fields["VERSION"]
	info.VersionID = fields["VERSION_ID"]
	info.PrettyName = fields["PRETTY_NAME"]

	if idLike := fields["ID_LIKE"]; idLike != "" {
		info.IDLike = strings.Fields(idLike)
	}

	info.Family = detectFamily(info.ID, info.IDLike)
	info.PkgManager = detectPkgManager(info.Family)
	info.InitSystem = detectInitSystem()

	return info
}

func parseOSRelease(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	fields := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		// Strip quotes from value
		value = strings.Trim(value, `"'`)
		fields[key] = value
	}
	return fields
}

func detectFamily(id string, idLike []string) Family {
	// Check ID first
	switch id {
	case "debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian", "elementary":
		return Debian
	case "rhel", "centos", "fedora", "rocky", "almalinux", "ol", "amzn":
		return RedHat
	case "opensuse-leap", "opensuse-tumbleweed", "sles":
		return SUSE
	case "alpine":
		return Alpine
	case "arch", "manjaro", "endeavouros":
		return Arch
	}

	// Fall back to ID_LIKE
	for _, like := range idLike {
		switch like {
		case "debian", "ubuntu":
			return Debian
		case "rhel", "centos", "fedora":
			return RedHat
		case "suse", "opensuse":
			return SUSE
		case "arch":
			return Arch
		}
	}

	return Unknown
}

func detectPkgManager(family Family) PkgManager {
	switch family {
	case Debian:
		return Apt
	case RedHat:
		// Prefer dnf over yum on modern systems
		if _, err := os.Stat("/usr/bin/dnf"); err == nil {
			return Dnf
		}
		return Yum
	case SUSE:
		return Zypper
	case Alpine:
		return Apk
	case Arch:
		return Pacman
	default:
		return NoPkg
	}
}

func detectInitSystem() InitSystem {
	// Check for systemd (most common)
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return Systemd
	}
	// Check for OpenRC
	if _, err := os.Stat("/run/openrc"); err == nil {
		return OpenRC
	}
	// Check PID 1
	if data, err := os.ReadFile("/proc/1/comm"); err == nil {
		comm := strings.TrimSpace(string(data))
		switch comm {
		case "systemd":
			return Systemd
		case "init":
			return SysVInit
		case "openrc-init":
			return OpenRC
		}
	}
	return NoInit
}
