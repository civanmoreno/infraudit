package osinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func writeOSRelease(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, "os-release")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectUbuntu(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="24.04"
PRETTY_NAME="Ubuntu 24.04 LTS"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.ID != "ubuntu" {
		t.Errorf("ID = %q, want ubuntu", info.ID)
	}
	if info.Family != Debian {
		t.Errorf("Family = %q, want debian", info.Family)
	}
	if info.PkgManager != Apt {
		t.Errorf("PkgManager = %q, want apt", info.PkgManager)
	}
	if info.VersionID != "24.04" {
		t.Errorf("VersionID = %q, want 24.04", info.VersionID)
	}
	if info.PrettyName != "Ubuntu 24.04 LTS" {
		t.Errorf("PrettyName = %q, want Ubuntu 24.04 LTS", info.PrettyName)
	}
	if len(info.IDLike) != 1 || info.IDLike[0] != "debian" {
		t.Errorf("IDLike = %v, want [debian]", info.IDLike)
	}
}

func TestDetectRHEL(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="Red Hat Enterprise Linux"
ID=rhel
ID_LIKE="fedora"
VERSION_ID="9.3"
PRETTY_NAME="Red Hat Enterprise Linux 9.3"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.ID != "rhel" {
		t.Errorf("ID = %q, want rhel", info.ID)
	}
	if info.Family != RedHat {
		t.Errorf("Family = %q, want redhat", info.Family)
	}
}

func TestDetectAlpine(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.21.0
PRETTY_NAME="Alpine Linux v3.21"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.Family != Alpine {
		t.Errorf("Family = %q, want alpine", info.Family)
	}
	if info.PkgManager != Apk {
		t.Errorf("PkgManager = %q, want apk", info.PkgManager)
	}
}

func TestDetectDebian(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.Family != Debian {
		t.Errorf("Family = %q, want debian", info.Family)
	}
}

func TestDetectFedora(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="Fedora Linux"
ID=fedora
VERSION_ID=41
PRETTY_NAME="Fedora Linux 41"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.Family != RedHat {
		t.Errorf("Family = %q, want redhat", info.Family)
	}
}

func TestDetectSUSE(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="openSUSE Leap"
ID=opensuse-leap
ID_LIKE="suse opensuse"
VERSION_ID="15.6"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.Family != SUSE {
		t.Errorf("Family = %q, want suse", info.Family)
	}
	if info.PkgManager != Zypper {
		t.Errorf("PkgManager = %q, want zypper", info.PkgManager)
	}
}

func TestDetectArch(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="Arch Linux"
ID=arch
PRETTY_NAME="Arch Linux"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.Family != Arch {
		t.Errorf("Family = %q, want arch", info.Family)
	}
	if info.PkgManager != Pacman {
		t.Errorf("PkgManager = %q, want pacman", info.PkgManager)
	}
}

func TestDetectUnknownFallsBackToIDLike(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="Pop!_OS"
ID=pop
ID_LIKE="ubuntu debian"
VERSION_ID="22.04"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	// pop is in the hardcoded list
	if info.Family != Debian {
		t.Errorf("Family = %q, want debian", info.Family)
	}
}

func TestDetectTrulyUnknown(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `NAME="MyCustomOS"
ID=mycustomos
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info := Detect()

	if info.Family != Unknown {
		t.Errorf("Family = %q, want unknown", info.Family)
	}
	if info.PkgManager != NoPkg {
		t.Errorf("PkgManager = %q, want unknown", info.PkgManager)
	}
}

func TestDetectMissingFile(t *testing.T) {
	// When the primary os-release path doesn't exist, it falls back to
	// /usr/lib/os-release. On a real system this will succeed, so we
	// just verify Arch is always populated regardless.
	dir := t.TempDir()
	osReleasePath = filepath.Join(dir, "nonexistent")
	Reset()

	info := Detect()

	if info.Arch == "" {
		t.Error("Arch should still be detected from runtime")
	}
}

func TestDetectFamilyFunction(t *testing.T) {
	tests := []struct {
		id     string
		idLike []string
		want   Family
	}{
		{"ubuntu", nil, Debian},
		{"centos", nil, RedHat},
		{"rocky", nil, RedHat},
		{"almalinux", nil, RedHat},
		{"alpine", nil, Alpine},
		{"manjaro", nil, Arch},
		{"sles", nil, SUSE},
		{"kali", nil, Debian},
		{"amzn", nil, RedHat},
		{"ol", nil, RedHat},
		{"elementary", nil, Debian},
		{"raspbian", nil, Debian},
		{"linuxmint", nil, Debian},
		{"unknown-distro", []string{"rhel", "fedora"}, RedHat},
		{"unknown-distro", []string{"arch"}, Arch},
		{"unknown-distro", []string{"suse"}, SUSE},
		{"totally-unknown", nil, Unknown},
	}

	for _, tt := range tests {
		got := detectFamily(tt.id, tt.idLike)
		if got != tt.want {
			t.Errorf("detectFamily(%q, %v) = %q, want %q", tt.id, tt.idLike, got, tt.want)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	dir := t.TempDir()
	content := `# This is a comment
NAME="Test OS"
ID=test
VERSION_ID="1.0"

# Empty lines and comments should be ignored
EXTRA_KEY=unquoted_value
SINGLE_QUOTED='single'
`
	path := filepath.Join(dir, "os-release")
	os.WriteFile(path, []byte(content), 0644)

	fields := parseOSRelease(path)

	if fields["NAME"] != "Test OS" {
		t.Errorf("NAME = %q, want 'Test OS'", fields["NAME"])
	}
	if fields["ID"] != "test" {
		t.Errorf("ID = %q, want 'test'", fields["ID"])
	}
	if fields["EXTRA_KEY"] != "unquoted_value" {
		t.Errorf("EXTRA_KEY = %q, want 'unquoted_value'", fields["EXTRA_KEY"])
	}
	if fields["SINGLE_QUOTED"] != "single" {
		t.Errorf("SINGLE_QUOTED = %q, want 'single'", fields["SINGLE_QUOTED"])
	}
}

func TestCaching(t *testing.T) {
	dir := t.TempDir()
	writeOSRelease(t, dir, `ID=ubuntu
NAME="Ubuntu"
`)
	osReleasePath = filepath.Join(dir, "os-release")
	Reset()

	info1 := Detect()
	info2 := Detect()

	if info1.ID != info2.ID {
		t.Error("Detect() should return cached result")
	}
}
