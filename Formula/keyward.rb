class Keyward < Formula
  desc "Keep shell secrets in macOS Keychain and resolve them through a local broker"
  homepage "https://github.com/veilux-lab/keyward"
  url "https://github.com/veilux-lab/keyward/releases/download/v0.1.7/keyward-0.1.7.tar.gz"
  version "0.1.7"
  sha256 "3f365b39bcf2a0f3ad1b7ae0b9d776b4b3627738a4f9e2588e49ec14afd7624b"
  license "MIT"

  bottle do
    root_url "https://github.com/veilux-lab/keyward/releases/download/v0.1.7"
    sha256 arm64_sequoia: "0c6c095ba9eb66f45fa95011ac37e0187fb7f45ee7b6764c87a97a134a6c8e26"
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
      The daemon starts automatically on first vault use, then at login.
      To start it immediately or re-enable it after service uninstall:
        #{opt_bin}/keyward service install

      After upgrading, restart it with keyward service install. Daemon upgrades
      may require approval to read previously stored Keychain items.

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
