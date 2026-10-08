class Keyward < Formula
  desc "Keep shell secrets in macOS Keychain and resolve them through a local broker"
  homepage "https://github.com/veilux-lab/keyward"
  url "https://github.com/veilux-lab/keyward/releases/download/v0.1.11/keyward-0.1.11.tar.gz"
  version "0.1.11"
  sha256 "814468ff0835c1b72d55643df9b09b40f13a3c413e5a85f694a7774ac12ef3d0"
  license "MIT"

  bottle do
    root_url "https://github.com/veilux-lab/keyward/releases/download/v0.1.11"
    sha256 arm64_sequoia: "e442f7d3d44a807fb5794e7976274dba7feec5a2b534eb4f921d28f43507ba2e"
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
      The Keyward daemon starts on first use, then at every login. After an
      upgrade, the next keyward command restarts it; macOS may ask once for
      Keychain access.
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
