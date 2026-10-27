class Keyward < Formula
  desc "Move shell secrets into a Keychain-keyed vault, resolved by a local broker"
  homepage "https://github.com/veilux-lab/keyward"
  url "https://github.com/veilux-lab/keyward/releases/download/v1.1.5/keyward-1.1.5.tar.gz"
  version "1.1.5"
  sha256 "639c9061907d5cd72004df674bb96b60de375f372f5d0b8eb6e8f55d4b6f6c0a"
  license "MIT"

  bottle do
    root_url "https://github.com/veilux-lab/keyward/releases/download/v1.1.5"
    sha256 arm64_sequoia: "f9c48e40ed209ffffe547500143ccbe45b36ad31544d8f2188278d5e39c24532"
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
      Get started:   keyward setup
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
