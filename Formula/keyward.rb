class Keyward < Formula
  desc "Keep shell secrets in macOS Keychain and resolve them through a local broker"
  homepage "https://github.com/veilux-lab/keyward"
  url "https://github.com/veilux-lab/keyward/releases/download/v0.1.8/keyward-0.1.8.tar.gz"
  version "0.1.8"
  sha256 "082f560b396c79c8131e03560811ee833b549eeb5db6065e28322baa033de6a7"
  license "MIT"

  bottle do
    root_url "https://github.com/veilux-lab/keyward/releases/download/v0.1.8"
    sha256 arm64_sequoia: "db5ead9eb9cc4925baa6ce3ba785ae0b4de0565943b545a0cff137e242c9ee57"
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
      The Keyward daemon starts on first use, then at every login.
        Start now or after an upgrade:  keyward service install
        Pause access:                   keyward service stop
        Remove everything:              keyward uninstall
      Use these rather than the brew services lines below. An upgrade may ask
      once for Keychain access.
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
