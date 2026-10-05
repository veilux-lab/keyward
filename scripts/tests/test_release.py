import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.events = self.root / "events"
        self.env = dict(os.environ, PATH=f"{self.tools}:{os.environ['PATH']}",
                        RUNNER_TEMP=str(self.root), EVENTS=str(self.events))

    def tool(self, name, body):
        path = self.tools / name
        path.write_text("#!/bin/bash\nset -eu\n" + body)
        path.chmod(0o755)

    def run_script(self, name, *args):
        return subprocess.run(["bash", str(SCRIPTS / name), *map(str, args)],
                              env=self.env, text=True, capture_output=True)

    def test_signing_requires_credentials_before_running_tools(self):
        for key in list(self.env):
            if key.startswith("APPLE_"):
                del self.env[key]
        result = self.run_script("sign-release.sh", "0.1.2", self.root / "release")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("APPLE_CERTIFICATE_P12_BASE64", result.stderr)
        self.assertFalse(self.events.exists())

    def test_bad_source_checksum_does_not_touch_homebrew(self):
        out = self.root / "release"
        (out / "Formula").mkdir(parents=True)
        (out / "keyward-0.1.2.tar.gz").write_text("fixture")
        (out / "Formula/keyward.rb").write_text('version "0.1.2"\nsha256 "' + "0" * 64 + '"\n')
        self.tool("brew", 'printf "brew\\n" >> "$EVENTS"\nexit 1\n')
        result = self.run_script("test-homebrew-release.sh", "0.1.2", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum", result.stderr)
        self.assertFalse(self.events.exists())

    def signing_fixture(self, status="Accepted", fail_sign=False):
        encoded = base64.b64encode(b"fixture certificate").decode()
        self.env.update(APPLE_CERTIFICATE_P12_BASE64=encoded[:12] + "\n" + encoded[12:] + "\n",
                        APPLE_CERTIFICATE_PASSWORD="private-fixture-password",
                        APPLE_SIGNING_IDENTITY="Developer ID Application: Fixture",
                        APPLE_NOTARY_KEY_P8="private-fixture-notary-key",
                        APPLE_NOTARY_KEY_ID="FIXTURE", APPLE_NOTARY_ISSUER_ID="fixture-issuer")
        self.tool("openssl", 'printf "openssl %s\\n" "$*" >> "$EVENTS"\nwhile [ "$#" -gt 0 ]; do\n if [ "$1" = -out ]; then printf fixture > "$2"; break; fi\n shift\ndone\n')
        self.tool("security", 'printf "security %s\\n" "$*" >> "$EVENTS"\n')
        self.tool("lipo", 'printf "lipo %s\\n" "$*" >> "$EVENTS"\nif [ "$1" = -create ]; then\n while [ "$1" != -output ]; do shift; done\n printf fixture > "$2"\nfi\n')
        self.tool("codesign", 'printf "codesign %s\\n" "$*" >> "$EVENTS"\n' + ("exit 1\n" if fail_sign else ""))
        self.tool("hdiutil", 'printf "hdiutil %s\\n" "$*" >> "$EVENTS"\nfor arg; do last="$arg"; done\nprintf fixture > "$last"\n')
        self.tool("spctl", 'printf "spctl %s\\n" "$*" >> "$EVENTS"\n')
        self.tool("xcrun", 'printf "xcrun %s\\n" "$*" >> "$EVENTS"\n' +
                  f'if [ "$1" = notarytool ]; then printf \'{{"status":"{status}"}}\\n\'; fi\n')
        out = self.root / "release"
        for arch in ("arm64", "amd64"):
            directory = out / "unsigned" / arch
            directory.mkdir(parents=True)
            (directory / "keyward").write_text("fixture")
        return out

    def test_signing_failure_cleans_up_and_never_submits(self):
        out = self.signing_fixture(fail_sign=True)
        result = self.run_script("sign-release.sh", "0.1.2", out)
        self.assertNotEqual(result.returncode, 0)
        events = self.events.read_text()
        self.assertIn("delete-keychain", events)
        self.assertNotIn("notarytool", events)
        self.assertFalse(list(self.root.glob("keyward-signing.*")))

    def test_notary_rejection_cannot_produce_publishable_package(self):
        out = self.signing_fixture(status="Invalid")
        result = self.run_script("sign-release.sh", "0.1.2", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("stapler staple", self.events.read_text())
        self.assertFalse((out / "keyward-0.1.2-darwin-universal.dmg").exists())

    def test_signing_acceptance_staples_and_keeps_credentials_out_of_argv(self):
        out = self.signing_fixture()
        result = self.run_script("sign-release.sh", "0.1.2", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text()
        self.assertIn("stapler staple", events)
        self.assertIn("stapler validate", events)
        self.assertIn("com.nwokolo24.keyward", events)
        self.assertIn("-R =anchor apple generic", events)
        for secret in (self.env["APPLE_CERTIFICATE_PASSWORD"], self.env["APPLE_NOTARY_KEY_P8"]):
            self.assertNotIn(secret, events + result.stdout + result.stderr)
        self.assertTrue((out / "keyward-0.1.2-darwin-universal.dmg").exists())
        self.assertFalse(list(self.root.glob("keyward-signing.*")))

    def publishing_fixture(self, existing="missing", remote_sha=None):
        self.env.update(GH_REPO="veilux-lab/keyward", GITHUB_SHA="a" * 40)
        self.tool("git", f'printf "{remote_sha or "a" * 40}\\trefs/tags/v0.1.2\\n"\n')
        out = self.root / "release"
        out.mkdir()
        for name in ("keyward-0.1.2.tar.gz", "keyward-0.1.2-darwin-universal.dmg", "SHA256SUMS", "release.json"):
            (out / name).write_text("fixture")
        state = self.root / "state.json"
        state.write_text(json.dumps({"isDraft": existing == "draft", "targetCommitish": "a" * 40,
                                    "assets": [] if existing == "incomplete" else
                                    [{"name": path.name} for path in out.iterdir()]}))
        self.env.update(PUBLISH_STATE=str(state), PUBLISH_SOURCE=str(out))
        self.tool("gh", 'printf "gh %s\\n" "$*" >> "$EVENTS"\n' +
                  ('if [ "$1 $2" = "release view" ]; then exit 1; fi\n' if existing == "missing" else
                   'if [ "$1 $2" = "release view" ]; then cat "$PUBLISH_STATE"; fi\n') +
                  'if [ "$1 $2" = "release download" ]; then\n while [ "$1" != --dir ]; do shift; done\n cp "$PUBLISH_SOURCE/keyward-0.1.2.tar.gz" "$2/"\nfi\n')
        return out

    def test_release_tag_is_pinned_to_tested_commit(self):
        out = self.publishing_fixture(remote_sha="b" * 40)
        result = self.run_script("publish-release.sh", "0.1.2", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())

    def test_missing_asset_cannot_be_published(self):
        out = self.publishing_fixture()
        (out / "keyward-0.1.2-darwin-universal.dmg").unlink()
        result = self.run_script("publish-release.sh", "0.1.2", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.events.exists())

    def test_new_release_uploads_all_assets_before_publication(self):
        out = self.publishing_fixture()
        result = self.run_script("publish-release.sh", "0.1.2", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text()
        self.assertIn("--target " + "a" * 40, events)
        self.assertIn("--draft", events)
        self.assertLess(events.index("release upload"), events.index("release edit"))

    def test_incomplete_public_release_is_not_overwritten(self):
        out = self.publishing_fixture(existing="incomplete")
        result = self.run_script("publish-release.sh", "0.1.2", out)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incomplete", result.stderr)
        events = self.events.read_text()
        self.assertNotIn("release upload", events)
        self.assertNotIn("release edit", events)

    def test_published_rerun_preserves_assets(self):
        out = self.publishing_fixture(existing="published")
        result = self.run_script("publish-release.sh", "0.1.2", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text()
        self.assertIn("release download", events)
        self.assertNotIn("release upload", events)
        self.assertNotIn("release edit", events)

    def test_draft_retry_resumes_before_publication(self):
        out = self.publishing_fixture(existing="draft")
        result = self.run_script("publish-release.sh", "0.1.2", out)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events.read_text()
        self.assertNotIn("release create", events)
        self.assertLess(events.index("release upload"), events.index("release edit"))


class FormulaUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.repo = self.root / "repo"
        self.git("init", "--bare", "--initial-branch=main", self.remote)
        self.git("clone", self.remote, self.repo)
        self.git("-C", self.repo, "config", "user.name", "Fixture")
        self.git("-C", self.repo, "config", "user.email", "fixture@example.invalid")
        (self.repo / "Formula").mkdir()
        (self.repo / "Formula/keyward.rb").write_text('version "0.1.1"\n')
        (self.repo / "Makefile").write_text("verify:\n\t@test ! -f fail-verify\n")
        self.git("-C", self.repo, "add", ".")
        self.git("-C", self.repo, "commit", "-qm", "fixture")
        self.git("-C", self.repo, "push", "origin", "main")
        self.formula = self.root / "keyward.rb"
        self.formula.write_text('version "0.1.2"\nsha256 "fixture"\n')

    def git(self, *args):
        result = subprocess.run(["git", *map(str, args)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def update(self):
        return subprocess.run(["bash", str(SCRIPTS / "update-homebrew.sh"), str(self.formula)],
                              cwd=self.repo, text=True, capture_output=True)

    def test_update_publishes_only_verified_formula_commit(self):
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        changed = self.git("--git-dir", self.remote, "diff", "--name-only", "HEAD~1", "HEAD")
        self.assertEqual(changed, "Formula/keyward.rb")
        self.assertEqual(self.git("--git-dir", self.remote, "show", "HEAD:Formula/keyward.rb"), self.formula.read_text().strip())

    def test_rerun_and_older_version_cannot_rewrite_or_downgrade(self):
        self.assertEqual(self.update().returncode, 0)
        first = self.git("--git-dir", self.remote, "rev-parse", "HEAD")
        self.assertEqual(self.update().returncode, 0)
        self.formula.write_text('version "0.1.1"\n')
        self.assertEqual(self.update().returncode, 0)
        self.assertEqual(first, self.git("--git-dir", self.remote, "rev-parse", "HEAD"))
        self.formula.write_text('version "0.1.2"\nsha256 "changed"\n')
        self.assertNotEqual(self.update().returncode, 0)
        self.assertEqual(first, self.git("--git-dir", self.remote, "rev-parse", "HEAD"))

    def test_failed_verification_leaves_remote_unchanged(self):
        (self.repo / "fail-verify").touch()
        self.git("-C", self.repo, "add", "fail-verify")
        self.git("-C", self.repo, "commit", "-qm", "failing fixture")
        self.git("-C", self.repo, "push", "origin", "main")
        first = self.git("--git-dir", self.remote, "rev-parse", "HEAD")
        result = self.update()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("make", result.stderr)
        self.assertEqual(first, self.git("--git-dir", self.remote, "rev-parse", "HEAD"))

    def test_retry_preserves_a_concurrent_main_commit(self):
        other = self.root / "other"
        self.git("clone", self.remote, other)
        self.git("-C", other, "config", "user.name", "Fixture")
        self.git("-C", other, "config", "user.email", "fixture@example.invalid")
        (other / "concurrent.txt").write_text("keep this change\n")
        self.git("-C", other, "add", "concurrent.txt")
        self.git("-C", other, "commit", "-qm", "concurrent fixture")
        hooks = self.root / "hooks"
        hooks.mkdir()
        marker = self.root / "pushed"
        hook = hooks / "pre-push"
        hook.write_text(f'#!/bin/bash\nset -eu\nif [ ! -f "{marker}" ]; then\n touch "{marker}"\n env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR -u GIT_PREFIX git -C "{other}" push origin main\nfi\n')
        hook.chmod(0o755)
        self.git("-C", self.repo, "config", "core.hooksPath", hooks)
        result = self.update()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rejected", result.stderr)
        self.assertEqual(self.git("--git-dir", self.remote, "show", "HEAD:concurrent.txt"), "keep this change")
        self.assertEqual(self.git("--git-dir", self.remote, "show", "HEAD:Formula/keyward.rb"), self.formula.read_text().strip())


if __name__ == "__main__":
    unittest.main()
