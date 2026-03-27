class Infraudit < Formula
  desc "Linux server security audit tool — 287 checks, CIS Benchmarks, single binary"
  homepage "https://github.com/civanmoreno/infraudit"
  version "2.1.0"
  license "BUSL-1.1"

  on_linux do
    on_intel do
      url "https://github.com/civanmoreno/infraudit/releases/download/v#{version}/infraudit-linux-amd64"
      sha256 "PLACEHOLDER_AMD64_SHA256"

      def install
        bin.install "infraudit-linux-amd64" => "infraudit"
      end
    end

    on_arm do
      url "https://github.com/civanmoreno/infraudit/releases/download/v#{version}/infraudit-linux-arm64"
      sha256 "PLACEHOLDER_ARM64_SHA256"

      def install
        bin.install "infraudit-linux-arm64" => "infraudit"
      end
    end
  end

  def caveats
    <<~EOS
      infraudit requires root access for most checks:
        sudo infraudit audit

      Quick start:
        sudo infraudit audit                    # Full audit
        sudo infraudit audit --category auth    # Auth checks only
        sudo infraudit audit --profile web-server  # Web server profile
        infraudit doctor                        # Check system readiness
        infraudit explain AUTH-001              # Explain a check

      Documentation: https://civanmoreno.github.io/infraudit/
    EOS
  end

  test do
    assert_match "infraudit v#{version}", shell_output("#{bin}/infraudit --version")
    assert_match "287", shell_output("#{bin}/infraudit list 2>&1")
  end
end
