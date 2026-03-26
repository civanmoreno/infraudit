package remote

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		input   string
		want    Host
		wantErr bool
	}{
		{"192.168.1.10", Host{Address: "192.168.1.10", Port: 22}, false},
		{"root@192.168.1.10", Host{User: "root", Address: "192.168.1.10", Port: 22}, false},
		{"root@192.168.1.10:2222", Host{User: "root", Address: "192.168.1.10", Port: 2222}, false},
		{"ubuntu@server.example.com", Host{User: "ubuntu", Address: "server.example.com", Port: 22}, false},
		{"deploy@db1.example.com:22", Host{User: "deploy", Address: "db1.example.com", Port: 22}, false},
		{"server.example.com:8022", Host{Address: "server.example.com", Port: 8022}, false},
		{"", Host{}, true},
		{"@host", Host{}, true},
		{"root@", Host{}, true},
		{"root@host:abc", Host{}, true},
		{"root@host:0", Host{}, true},
		{"root@host:99999", Host{}, true},
	}

	for _, tt := range tests {
		got, err := ParseHost(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseHost(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if got.User != tt.want.User || got.Address != tt.want.Address || got.Port != tt.want.Port {
			t.Errorf("ParseHost(%q) = %+v, want %+v", tt.input, got, tt.want)
		}
	}
}

func TestHostString(t *testing.T) {
	tests := []struct {
		host Host
		want string
	}{
		{Host{Address: "192.168.1.10", Port: 22}, "192.168.1.10"},
		{Host{User: "root", Address: "192.168.1.10", Port: 22}, "root@192.168.1.10"},
		{Host{User: "root", Address: "192.168.1.10", Port: 2222}, "root@192.168.1.10:2222"},
		{Host{Address: "server.com", Port: 8022}, "server.com:8022"},
	}

	for _, tt := range tests {
		got := tt.host.String()
		if got != tt.want {
			t.Errorf("Host%+v.String() = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestParseHostsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")

	content := `# Production servers
root@web1.example.com
root@web2.example.com:2222

# Database
deploy@db1.example.com
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	hosts, err := ParseHostsFile(path)
	if err != nil {
		t.Fatalf("ParseHostsFile: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(hosts))
	}
	if hosts[0].User != "root" || hosts[0].Address != "web1.example.com" {
		t.Errorf("host[0] = %+v", hosts[0])
	}
	if hosts[1].Port != 2222 {
		t.Errorf("host[1] port = %d, want 2222", hosts[1].Port)
	}
	if hosts[2].User != "deploy" || hosts[2].Address != "db1.example.com" {
		t.Errorf("host[2] = %+v", hosts[2])
	}
}

func TestParseHostsFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	os.WriteFile(path, []byte("# only comments\n\n"), 0600)

	_, err := ParseHostsFile(path)
	if err == nil {
		t.Fatal("expected error for empty hosts file")
	}
}

func TestParseHostsFileNotFound(t *testing.T) {
	_, err := ParseHostsFile("/nonexistent/hosts.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseHostsFileInvalidLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	os.WriteFile(path, []byte("root@host:abc\n"), 0600)

	_, err := ParseHostsFile(path)
	if err == nil {
		t.Fatal("expected error for invalid host line")
	}
}

func TestSSHArgs(t *testing.T) {
	tests := []struct {
		name  string
		host  Host
		extra []string
		check func([]string) bool
	}{
		{
			name:  "basic host",
			host:  Host{Address: "server.com", Port: 22},
			extra: []string{"uname", "-m"},
			check: func(args []string) bool {
				return contains(args, "server.com") && contains(args, "uname") && !containsFlag(args, "-p")
			},
		},
		{
			name: "custom port",
			host: Host{Address: "server.com", Port: 2222},
			check: func(args []string) bool {
				return containsFlag(args, "-p") && contains(args, "2222")
			},
		},
		{
			name: "with user",
			host: Host{User: "root", Address: "server.com", Port: 22},
			check: func(args []string) bool {
				return contains(args, "root@server.com")
			},
		},
		{
			name: "with identity",
			host: Host{Address: "server.com", Port: 22, Identity: "/home/user/.ssh/id_rsa"},
			check: func(args []string) bool {
				return containsFlag(args, "-i") && contains(args, "/home/user/.ssh/id_rsa")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := sshArgs(tt.host, tt.extra...)
			if !tt.check(args) {
				t.Errorf("sshArgs(%+v, %v) = %v", tt.host, tt.extra, args)
			}
			// BatchMode should always be present
			if !contains(args, "BatchMode=yes") {
				t.Errorf("sshArgs missing BatchMode=yes: %v", args)
			}
		})
	}
}

func TestMapArch(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"x86_64", "amd64", false},
		{"aarch64", "arm64", false},
		{"arm64", "arm64", false},
		{"amd64", "amd64", false},
		{"i386", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		got, err := mapArch(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("mapArch(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("mapArch(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func containsFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}
