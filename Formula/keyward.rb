class Keyward < Formula
  desc "Move shell secrets into a Keychain-keyed vault, resolved by a local broker"
  homepage "https://github.com/veilux-lab/keyward"
  url "https://github.com/veilux-lab/keyward/releases/download/v0.1.16/keyward-0.1.16.tar.gz"
  version "0.1.16"
  sha256 "79c55f53fcb56fe196918623c2cab0f86dd24f8985fd8913c2e0a10cb63fa963"
  license "MIT"

  bottle do
    root_url "https://github.com/veilux-lab/keyward/releases/download/v0.1.16"
    sha256 arm64_sequoia: "b7d02f5ed748edffb71feea75bb0ba4b7380e7c54784865728674576b63c978b"
  end

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
      The Keyward daemon starts on first use, then at every login, and writes
      ~/.agents/keyward.md, instructions for AI agents. After an upgrade, the
      next keyward command restarts it; macOS may ask once for Keychain access.
        Start now:          keyward service install
        Pause access:       keyward service stop
        Remove everything:  keyward uninstall
      Use these rather than the brew services lines below.
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
