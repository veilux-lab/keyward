class Keyward < Formula
  desc "Keep shell secrets in macOS Keychain and resolve them through a local broker"
  homepage "https://github.com/veilux-lab/keyward"
  url "https://github.com/veilux-lab/keyward/releases/download/v0.1.1/keyward-0.1.1.tar.gz"
  version "0.1.1"
  sha256 "a8a3b95e941541d29565b5cca44ba157ef4a9db5203018c8a9c9ecc2cfb0241a"
  license "MIT"

  depends_on "go" => :build
  depends_on :macos

  def install
    ENV["CGO_ENABLED"] = "1"
    ENV["GOTOOLCHAIN"] = "local"
    ldflags = "-X github.com/veilux-lab/keyward/internal/cli.Version=#{version} " \
              "-X main.homebrewExecutable=#{HOMEBREW_PREFIX}/bin/brew"
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/keyward"
  end

  service do
    name macos: "com.veilux-lab.keyward.homebrew"
    run [opt_bin/"keyward", "daemon"]
    keep_alive true
    working_dir Dir.home
    log_path File::NULL
    error_log_path File::NULL
  end

  def caveats
    <<~EOS
      Start the broker now and at login:
        #{opt_bin}/keyward service install

      After upgrading, restart it with keyward service install. Source-built
      daemon upgrades may require approval to read previously stored Keychain items.
      This formula does not install the signed Keyward.app companion.

      Before uninstalling, run keyward restore <file>... if you want secrets
      returned to your files, then keyward service uninstall and brew uninstall keyward.
      Restoration requires explicit yes and writes plaintext secrets. Keychain items
      are retained; brew uninstall never restores secrets for you.
    EOS
  end

  test do
    ENV["KEYWARD_LOG_DIR"] = (testpath/"logs").to_s
    assert_equal "#{version}\n", shell_output("#{bin}/keyward version")
    system "/usr/bin/env", "-i", "HOME=#{testpath}", "KEYWARD_LOG_DIR=#{testpath}/logs",
           bin/"keyward", "run", "--", "/bin/echo", "homebrew-probe"
    assert_match '"operation":"exec"', (testpath/"logs/activity.jsonl").read
  end
end
