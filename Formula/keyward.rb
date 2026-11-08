class Keyward < Formula
  desc "Move shell secrets into a Keychain-keyed vault, resolved by a local broker"
  homepage "https://github.com/veilux-lab/keyward"
  url "https://github.com/veilux-lab/keyward/releases/download/v1.3.0/keyward-1.3.0.tar.gz"
  version "1.3.0"
  sha256 "c441820d2adfb7ad2314d494e9a493d9a22c9e666dd4d4d316e216349b167c69"
  license "MIT"

  bottle do
    root_url "https://github.com/veilux-lab/keyward/releases/download/v1.3.0"
    sha256 arm64_sequoia: "64c7bc470c2775b380aed973fec7f0c1923ffb76229b2713e61220e5e8479859"
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
      Get started:   keyward setup, in Terminal.app
      Then use:      keyward run --only VAR -- <command>
      More:          keyward help. Remove with keyward uninstall, not brew uninstall.
      Ignore the brew services lines below; keyward starts its own daemon.
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
