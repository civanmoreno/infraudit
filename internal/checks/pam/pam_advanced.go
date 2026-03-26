package pam

import (
	"os"
	"strconv"
	"strings"

	"github.com/civanmoreno/infraudit/internal/check"
)

func init() {
	check.Register(&pamNullok{})
	check.Register(&pamSecuretty{})
	check.Register(&pamDenyRoot{})
	check.Register(&loginDefsUID{})
	check.Register(&loginDefsGID{})
	check.Register(&loginDefsUmask{})
	check.Register(&loginDefsEncrypt{})
	check.Register(&pamSuWheel{})
}

// PAM-006: No nullok in PAM
type pamNullok struct{}

func (c *pamNullok) ID() string               { return "PAM-006" }
func (c *pamNullok) Name() string             { return "No nullok in PAM authentication" }
func (c *pamNullok) Category() string         { return "pam" }
func (c *pamNullok) Severity() check.Severity { return check.High }
func (c *pamNullok) Description() string {
	return "Ensure nullok is not used in PAM authentication modules"
}

func (c *pamNullok) Run() check.Result {
	for _, path := range []string{"/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "nullok") {
				return check.Result{Status: check.Fail, Message: "nullok found in " + path, Remediation: "Remove nullok from PAM auth configuration in " + path}
			}
		}
	}
	return check.Result{Status: check.Pass, Message: "No nullok in PAM authentication"}
}

// PAM-007: securetty configured
type pamSecuretty struct{}

func (c *pamSecuretty) ID() string               { return "PAM-007" }
func (c *pamSecuretty) Name() string             { return "securetty restricts root terminals" }
func (c *pamSecuretty) Category() string         { return "pam" }
func (c *pamSecuretty) Severity() check.Severity { return check.Medium }
func (c *pamSecuretty) Description() string {
	return "Ensure /etc/securetty restricts root login to console"
}

func (c *pamSecuretty) Run() check.Result {
	if _, err := os.Stat("/etc/securetty"); os.IsNotExist(err) {
		return check.Result{Status: check.Pass, Message: "/etc/securetty not present (default secure on modern systems)"}
	}
	data, err := os.ReadFile("/etc/securetty")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/securetty"}
	}
	lines := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines++
		}
	}
	if lines > 6 {
		return check.Result{Status: check.Warn, Message: "securetty allows many terminals", Remediation: "Reduce entries in /etc/securetty to only necessary consoles"}
	}
	return check.Result{Status: check.Pass, Message: "securetty is configured restrictively"}
}

// PAM-008: Deny root login except on securetty
type pamDenyRoot struct{}

func (c *pamDenyRoot) ID() string               { return "PAM-008" }
func (c *pamDenyRoot) Name() string             { return "pam_securetty enabled for root" }
func (c *pamDenyRoot) Category() string         { return "pam" }
func (c *pamDenyRoot) Severity() check.Severity { return check.Medium }
func (c *pamDenyRoot) Description() string {
	return "Ensure pam_securetty is used to restrict root login"
}

func (c *pamDenyRoot) Run() check.Result {
	data, err := os.ReadFile("/etc/pam.d/login")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/pam.d/login"}
	}
	if strings.Contains(string(data), "pam_securetty") {
		return check.Result{Status: check.Pass, Message: "pam_securetty is configured in /etc/pam.d/login"}
	}
	return check.Result{Status: check.Warn, Message: "pam_securetty not found in /etc/pam.d/login"}
}

// PAM-009 to PAM-012: login.defs settings
type loginDefsUID struct{}

func (c *loginDefsUID) ID() string               { return "PAM-009" }
func (c *loginDefsUID) Name() string             { return "UID_MIN configured correctly" }
func (c *loginDefsUID) Category() string         { return "pam" }
func (c *loginDefsUID) Severity() check.Severity { return check.Low }
func (c *loginDefsUID) Description() string      { return "Ensure UID_MIN is set to 1000 in login.defs" }

func (c *loginDefsUID) Run() check.Result {
	val := loginDefsValue("UID_MIN")
	if val == "" {
		return check.Result{Status: check.Warn, Message: "UID_MIN not set in /etc/login.defs"}
	}
	n, _ := strconv.Atoi(val)
	if n == 1000 {
		return check.Result{Status: check.Pass, Message: "UID_MIN = 1000"}
	}
	return check.Result{Status: check.Warn, Message: "UID_MIN = " + val + " (expected 1000)"}
}

type loginDefsGID struct{}

func (c *loginDefsGID) ID() string               { return "PAM-010" }
func (c *loginDefsGID) Name() string             { return "GID_MIN configured correctly" }
func (c *loginDefsGID) Category() string         { return "pam" }
func (c *loginDefsGID) Severity() check.Severity { return check.Low }
func (c *loginDefsGID) Description() string      { return "Ensure GID_MIN is set to 1000 in login.defs" }

func (c *loginDefsGID) Run() check.Result {
	val := loginDefsValue("GID_MIN")
	if val == "" {
		return check.Result{Status: check.Warn, Message: "GID_MIN not set in /etc/login.defs"}
	}
	n, _ := strconv.Atoi(val)
	if n == 1000 {
		return check.Result{Status: check.Pass, Message: "GID_MIN = 1000"}
	}
	return check.Result{Status: check.Warn, Message: "GID_MIN = " + val + " (expected 1000)"}
}

type loginDefsUmask struct{}

func (c *loginDefsUmask) ID() string               { return "PAM-011" }
func (c *loginDefsUmask) Name() string             { return "UMASK configured in login.defs" }
func (c *loginDefsUmask) Category() string         { return "pam" }
func (c *loginDefsUmask) Severity() check.Severity { return check.Medium }
func (c *loginDefsUmask) Description() string {
	return "Ensure UMASK is 027 or more restrictive in login.defs"
}

func (c *loginDefsUmask) Run() check.Result {
	val := loginDefsValue("UMASK")
	if val == "" {
		return check.Result{Status: check.Warn, Message: "UMASK not set in /etc/login.defs", Remediation: "Set UMASK 027 in /etc/login.defs"}
	}
	if val >= "027" {
		return check.Result{Status: check.Pass, Message: "UMASK = " + val}
	}
	return check.Result{Status: check.Fail, Message: "UMASK = " + val + " (too permissive)", Remediation: "Set UMASK 027 in /etc/login.defs"}
}

type loginDefsEncrypt struct{}

func (c *loginDefsEncrypt) ID() string               { return "PAM-012" }
func (c *loginDefsEncrypt) Name() string             { return "ENCRYPT_METHOD is SHA512 or yescrypt" }
func (c *loginDefsEncrypt) Category() string         { return "pam" }
func (c *loginDefsEncrypt) Severity() check.Severity { return check.High }
func (c *loginDefsEncrypt) Description() string {
	return "Ensure password hashing algorithm is SHA512 or yescrypt"
}

func (c *loginDefsEncrypt) Run() check.Result {
	val := loginDefsValue("ENCRYPT_METHOD")
	if val == "" {
		return check.Result{Status: check.Warn, Message: "ENCRYPT_METHOD not set in /etc/login.defs"}
	}
	upper := strings.ToUpper(val)
	if upper == "SHA512" || upper == "YESCRYPT" {
		return check.Result{Status: check.Pass, Message: "ENCRYPT_METHOD = " + val}
	}
	return check.Result{Status: check.Fail, Message: "ENCRYPT_METHOD = " + val + " (weak)", Remediation: "Set ENCRYPT_METHOD SHA512 in /etc/login.defs"}
}

// PAM-013: pam_wheel for su
type pamSuWheel struct{}

func (c *pamSuWheel) ID() string               { return "PAM-013" }
func (c *pamSuWheel) Name() string             { return "su restricted to wheel group" }
func (c *pamSuWheel) Category() string         { return "pam" }
func (c *pamSuWheel) Severity() check.Severity { return check.Medium }
func (c *pamSuWheel) Description() string      { return "Ensure access to su is restricted via pam_wheel" }

func (c *pamSuWheel) Run() check.Result {
	data, err := os.ReadFile("/etc/pam.d/su")
	if err != nil {
		return check.Result{Status: check.Error, Message: "Cannot read /etc/pam.d/su"}
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "pam_wheel.so") && strings.Contains(line, "required") {
			return check.Result{Status: check.Pass, Message: "pam_wheel.so required is configured for su"}
		}
	}
	return check.Result{Status: check.Warn, Message: "pam_wheel.so not required in /etc/pam.d/su", Remediation: "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su"}
}

func loginDefsValue(key string) string {
	data, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == key {
			return fields[1]
		}
	}
	return ""
}
