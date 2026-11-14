package doctor_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/migrate"
	"github.com/veilux-lab/keyward/internal/vault"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// store builds a vault where each name carries the given note.
func store(t *testing.T, entries map[string]string) *vault.Memory {
	t.Helper()
	s := vault.NewMemory()
	for name, note := range entries {
		if err := s.Put(name, vault.NewSecret([]byte("value")), note); err != nil {
			t.Fatalf("Put(%s): %v", name, err)
		}
	}
	return s
}

// printed is all doctor prints of r, plain.
func printed(r *doctor.Report) string {
	return r.Render(doctor.Format{}) + r.Summary(doctor.Format{}, r.Checks(), nil) + doctor.Format{}.Verdict(r.Checks(), r.Problems())
}

func names(findings []doctor.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Name)
	}
	return out
}

// ===========================================================================
// Scanning
// ===========================================================================

func TestFindsReferencesWithLineNumbers(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export EDITOR=vim\nexport A='cap://alpha'\n\nexport B=\"cap://beta\"\n")

	r, err := doctor.Run(store(t, map[string]string{"alpha": "", "beta": ""}), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(r.Dangling) != 0 {
		t.Errorf("Dangling = %v, want none", r.Dangling)
	}
	if got := strings.Join(r.Referenced, ","); got != "alpha,beta" {
		t.Errorf("Referenced = %v, want alpha,beta", r.Referenced)
	}
}

// References are found by text, not by parsing a format, so the same scan works
// for shell files, .env files, and the JSON and TOML that MCP servers use.
func TestFindsReferencesInAnyFileFormat(t *testing.T) {
	dir := t.TempDir()
	js := write(t, dir, "mcp.json", `{"env": {"SPLUNK_MCP_TOKEN": "cap://splunk-mcp-token"}}`)
	toml := write(t, dir, "config.toml", "[server.env]\nTOKEN = \"cap://toml-token\"\n")

	r, err := doctor.Run(store(t, map[string]string{"splunk-mcp-token": "", "toml-token": ""}), []string{js, toml}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Referenced) != 2 {
		t.Errorf("Referenced = %v, want both references found", r.Referenced)
	}
}

// doctor reads files that still hold plaintext in their unmigrated lines. Nothing
// it reports may echo their contents.
func TestReportNeverEchoesFileContents(t *testing.T) {
	dir := t.TempDir()
	const secret = "ghp_stillInPlaintextValue0123456789"
	rc := write(t, dir, ".zshrc", "export LEFTOVER="+secret+"\nexport A='cap://alpha'\n")

	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out := printed(r); strings.Contains(out, secret) {
		t.Errorf("the report echoed a plaintext secret:\n%s", out)
	}
}

// ===========================================================================
// Dangling references — the class that breaks a command today
// ===========================================================================

func TestDanglingReferences(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://present'\nexport B='cap://absent'\n")

	r, err := doctor.Run(store(t, map[string]string{"present": ""}), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(r.Dangling) != 1 {
		t.Fatalf("Dangling = %v, want one", r.Dangling)
	}
	d := r.Dangling[0]
	if d.Name != "absent" || d.File != rc || d.Line != 2 {
		t.Errorf("Dangling[0] = %+v, want absent at %s:2", d, rc)
	}
	if len(r.Problems()) == 0 {
		t.Error("Problems() is empty with a dangling reference")
	}
	if out := r.Render(doctor.Format{}); !strings.Contains(out, "keyward add absent") {
		t.Errorf("the report does not say how to fix it:\n%s", out)
	}
}

// A reference that cannot be parsed will fail at run time, so it is a problem too.
func TestMalformedReferences(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://-leading-hyphen'\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Malformed) != 1 {
		t.Fatalf("Malformed = %v, want one", r.Malformed)
	}
	if len(r.Problems()) == 0 {
		t.Error("Problems() is empty with a malformed reference")
	}
}

// ===========================================================================
// Plaintext — credentials still where an agent can read them
// ===========================================================================

// Fake credentials. The report says where each one is, never what it is.
const (
	githubToken = "ghp_FakeDoctorToken000000000000000000000"
	dbPassword  = "FakeDoctorPassw0rd"
	namedValue  = "correct-horse-battery-staple-9271"
)

// A token that migrate skipped, or that was added since, is as readable as before
// keyward. Its own form says what it is, so it fails doctor, and its line is not
// advised to be marked as holding no secret.
func TestACredentialInPlaintextIsAProblem(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://alpha'\nexport GITHUB_TOKEN="+githubToken+"\n")
	env := write(t, dir, ".env", "DATABASE_URL=postgresql://app:"+dbPassword+"@db.internal:5432/app\n")

	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc, env}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got []string
	for _, p := range r.Plaintext {
		got = append(got, fmt.Sprintf("%s:%d %s %v", filepath.Base(p.File), p.Line, p.Name, p.KnownShape))
	}
	if want := ".zshrc:2 GITHUB_TOKEN true,.env:1 DATABASE_URL true"; strings.Join(got, ",") != want {
		t.Errorf("Plaintext = %v, want %s", got, want)
	}
	if got := strings.Join(r.Problems(), "; "); got != "2 credential(s) in plaintext" {
		t.Errorf("Problems() = %q", got)
	}
	out := printed(r)
	if got, want := row(out, rc+":2 "), rc+":2 migrate GITHUB_TOKEN a GitHub token"; got != want {
		t.Errorf("the row for GITHUB_TOKEN reads %q, want %q:\n%s", got, want, out)
	}
	if got, want := row(out, env+":1 "), env+":1 migrate DATABASE_URL the value is a URL containing credentials"; got != want {
		t.Errorf("the row for DATABASE_URL reads %q, want %q:\n%s", got, want, out)
	}
	for _, want := range []string{
		"move it with keyward migrate on the file it is in (preview with --dry-run), or store it with keyward add NAME and set the variable to 'cap://NAME' " +
			"e.g. keyward add github-token and set GITHUB_TOKEN to 'cap://github-token'",
	} {
		if !strings.Contains(flat(out), want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if want := "\n  Then rotate each one, and store its new value with keyward add --force NAME.\n" +
		"  AI agents must not open these lines or print these configs; ask the user to fix them.\n"; !strings.Contains(out, want) {
		t.Errorf("the report lacks %q:\n%s", want, out)
	}
	if strings.Contains(out, migrate.IgnoreMarker) {
		t.Errorf("the report advises marking a credential's line:\n%s", out)
	}
	for _, value := range []string{githubToken, dbPassword} {
		if strings.Contains(out, value) {
			t.Errorf("the report printed a value:\n%s", out)
		}
	}
}

// A name or randomness only suggests a credential, and so does a value that only
// starts like a key: AUTH is in GIT_AUTHOR_EMAIL, sk-SK is a locale, ASIA a region,
// and a PEM block a public key. These are listed so the user can judge them, but
// they do not fail doctor.
func TestValuesThatMayBeCredentialsAreListedNotFailed(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export GIT_AUTHOR_EMAIL=someone@example.com\n"+
		"export BUILD_ID=Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i\nexport LOCALE=sk-SK\nexport EDITOR=vim\n")
	env := write(t, dir, ".env", "SUPPORTED_LOCALES=sk-SK,cs-CZ,de-DE,en-US\nDEPLOY_REGIONS=ASIA,EUROPE,AMERICAS,AFRICA\n"+
		`JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"`+"\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc, env}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got []string
	for _, p := range r.Plaintext {
		got = append(got, p.Name)
	}
	if strings.Join(got, ",") != "GIT_AUTHOR_EMAIL,BUILD_ID,LOCALE,SUPPORTED_LOCALES,DEPLOY_REGIONS,JWT_PUBLIC_KEY" {
		t.Errorf("Plaintext = %v", got)
	}
	if p := r.Problems(); len(p) > 0 {
		t.Errorf("Problems() = %v, want none", p)
	}
	out := r.Render(doctor.Format{})
	if !strings.Contains(out, "! 6 value(s) that may be credentials\n") || !strings.Contains(flat(out), "# "+migrate.IgnoreMarker+" yourself, and keyward leaves the line alone") {
		t.Errorf("the report does not list them with a way to mark one as no secret:\n%s", out)
	}
	if strings.Contains(out, "in plaintext") {
		t.Errorf("the report calls them credentials:\n%s", out)
	}
}

// A token migrate cannot move, in a comment, an alias or the comment beside a
// reference, is as readable as one in an assignment. One of a known shape fails
// doctor too. It is named by file, line and what holds it, never shown, and is
// removed by hand rather than moved.
func TestACredentialMigrateCannotMoveIsAProblem(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://alpha' # was "+githubToken+"\n"+
		"# export GITHUB_TOKEN="+githubToken+"\n"+
		"alias gh='GITHUB_TOKEN="+githubToken+" gh'\n")
	env := write(t, dir, ".env", "DATABASE_URL = postgresql://app:"+dbPassword+"@db.internal:5432/app\n")

	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc, env}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got []string
	for _, u := range r.Unmovable {
		got = append(got, fmt.Sprintf("%s:%d %s %v", filepath.Base(u.File), u.Line, u.Kind, u.KnownShape))
	}
	if want := ".zshrc:1 trailer true,.zshrc:2 comment true,.zshrc:3 alias true,.env:1 unsupported syntax true"; strings.Join(got, ",") != want {
		t.Errorf("Unmovable = %v, want %s", got, want)
	}
	if len(r.Plaintext) != 0 {
		t.Errorf("Plaintext = %+v, want none", r.Plaintext)
	}
	if got := strings.Join(r.Problems(), "; "); got != "4 credential(s) in plaintext" {
		t.Errorf("Problems() = %q", got)
	}
	out := printed(r)
	for start, want := range map[string]string{
		rc + ":1 ":  rc + ":1 edit trailer a GitHub token",
		rc + ":2 ":  rc + ":2 edit comment a GitHub token",
		rc + ":3 ":  rc + ":3 edit alias a GitHub token",
		env + ":1 ": env + ":1 edit unsupported syntax a URL with a password",
	} {
		if got := row(out, start); got != want {
			t.Errorf("the row reads %q, want %q:\n%s", got, want, out)
		}
	}
	if want := "To fix each: edit remove it by hand in an editor Then rotate"; !strings.Contains(flat(out), want) {
		t.Errorf("the report lacks %q:\n%s", want, out)
	}
	for _, value := range []string{githubToken, dbPassword} {
		if strings.Contains(out, value) {
			t.Errorf("the report printed a value:\n%s", out)
		}
	}
}

// Text migrate cannot move is judged as a value is: a name, randomness, or a value
// too short for its prefix only suggests a credential, so AUTH in a commented-out
// GIT_AUTHOR_EMAIL does not fail doctor either.
func TestTextMigrateCannotMoveIsListedWhenItOnlyMayBeACredential(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "# export GIT_AUTHOR_EMAIL=someone@example.com\n"+
		"alias build='make BUILD_ID=Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i'\n"+
		"export EDITOR=vim # 0123456789abcdef0123456789abcdef\n"+
		"# old: ghp_Ab3dEf6hIj9l\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got []string
	for _, u := range r.Unmovable {
		got = append(got, fmt.Sprintf("%d %s %v", u.Line, u.Kind, u.KnownShape))
	}
	if want := "1 comment false,2 alias false,3 trailer false,4 comment false"; strings.Join(got, ",") != want {
		t.Errorf("Unmovable = %v, want %s", got, want)
	}
	if p := r.Problems(); len(p) > 0 {
		t.Errorf("Problems() = %v, want none", p)
	}
	out := r.Render(doctor.Format{})
	if got, want := row(out, rc+":2 "), rc+":2 edit alias a random 36-character token"; got != want {
		t.Errorf("the row reads %q, want %q:\n%s", got, want, out)
	}
	for _, want := range []string{"! 4 value(s) that may be credentials", "If one is a credential: edit remove it by hand in an editor Rotate",
		"Rotate each one that is a credential, and store its new value with keyward add --force NAME. " +
			"If one holds no secret, end its line with # " + migrate.IgnoreMarker + " yourself, and keyward leaves the line alone (shell and .env files only); an AI agent must not. " +
			"AI agents must not open these lines or print these configs; ask the user to judge them."} {
		if !strings.Contains(flat(out), want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n  AI agents must not open these lines or print these configs; ask the user to judge them.\n") {
		t.Errorf("the report does not end with what AI agents must not do:\n%s", out)
	}
	if strings.Contains(out, "in plaintext") {
		t.Errorf("the report calls them credentials:\n%s", out)
	}
}

// Fake values of the shapes doctor labels. Each one shaped like a provider's key
// is split, so secret scanners do not report it.
const (
	hex32        = "9f8e7d6c5b4a39281706fedcba098765"
	mixedToken   = "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i"
	awsSecretKey = "wJalrXUtnFEMI/K7MDENG" + "/bPxRfiCYEXAMPLEKEY"
)

// doctor says what each line it lists holds, in plain words built from fixed text
// and lengths, never from the line. A name in a comment can be a token itself, so
// a label names none.
func TestDoctorSaysWhatEachLineHoldsWithoutShowingIt(t *testing.T) {
	for _, tc := range []struct{ line, value, label string }{
		{"# old: %s", "ghp_" + "FakeLabelToken0000000000000000000000", "a GitHub token"},
		{"# old: %s", "glpat-" + "FakeLabelGitLab00000", "a GitLab token"},
		{"# old: %s", "sk-proj-" + "FakeLabelOpenAI0000000000", "an OpenAI-style API key"},
		{"# old: %s", "sk-ant-api03-" + "FakeLabelAnthropic000000", "an Anthropic API key"},
		{"# old: %s", "xoxb-" + "123456789012-FakeLabelSlack00", "a Slack token"},
		{"# old: %s", "AKIA" + "IOSFODNN7EXAMPLE", "an AWS access key ID"},
		{"# old: %s", "ASIA" + "IOSFODNN7EXAMPLE", "a temporary AWS access key ID"},
		{"# old: %s", awsSecretKey, "an AWS secret key"},
		{"# old: %s", "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJsYWJlbCJ9.c2lnbmF0dXJl", "a JWT"},
		{"# old: %s", "eyJraWQiOiJsYWJlbCIsImFsZyI6IkhTMjU2In0", "base64-encoded JSON"},
		{"# old: %s", "AIza" + "SyFakeLabelGoogleKey0000000000000000", "a Google API key"},
		{"# old: %s", "hvs." + "FakeLabelVaultToken0000", "a HashiCorp Vault token"},
		{"# old: %s", "npm_" + "FakeLabelNpmToken0000000000000000000", "an npm token"},
		{"# old: %s", "dop_v1_" + hex32 + hex32, "a DigitalOcean token"},
		{"# old: %s", "shpat_" + hex32, "a Shopify token"},
		{"# old: %s", "sq0atp-" + "FakeLabelSquare000000", "a Square token"},
		{"# old: %s", "sk_live_" + "FakeLabelStripe000000000", "a Stripe secret key"},
		{"# old: %s", "sk_test_" + "FakeLabelStripe000000000", "a Stripe test key"},
		{"# old: %s", "rk_live_" + "FakeLabelStripe000000000", "a Stripe restricted key"},
		{"# old: %s", "SG." + "FakeLabelSendGrid.FakeLabelSendGridKey00", "a SendGrid API key"},
		{"# Authorization: %s", "Bearer FakeLabelBearerToken000", "a bearer token"},
		{"# Authorization: %s", "Basic ZmFrZTpsYWJlbC1wYXNzd29yZA==", "a basic-auth credential"},
		{"# %s", "postgres://app:FakeLabelPassw0rd@db.internal/app", "a URL with a password"},
		{"# old: %s", hex32, "32 hex characters"},
		{"# old: %s", "0123456789abcdef0123456789abcdef" + "-us12", "32 hex characters"},
		{"# old: %s", "3f2a9c1e-7b4d-4e8f-9a6b-" + "2c1d0e5f7a8b", "a UUID"},
		{"# old: %s", mixedToken, "a random 36-character token"},
		{"# old: %s", "Ab3d/Ef6hIj9lMn2pQr5tUv8xYz01/AbCdEf6h+Ij9l", "a 43-character base64 key"},
		{"# old: %s", "AKIA" + "IOSFODNN7EXAMPLE " + awsSecretKey, "an AWS access key ID and an AWS secret key"},
		{"# old: %s", hex32 + " " + hex32, "runs of 32 hex characters"},
		{"# export GITHUB_TOKEN=%s", "ghp_" + "FakeLabelCommented000000000000000000", "a GitHub token"},
		{"# export API_TOKEN=%s", "correct-horse-battery-staple", "a value named like a credential"},
		{"# export SESSION_TOKEN=%s", "0f1e2d3c4b5a69788796a5b4c3d2e1f0", "a value named like a credential: 32 hex characters"},
		{"# export DATABASE_URL=%s", "postgres://app:FakeLabelPassw0rd@db.internal:5432/app", "a URL with a password"},
		{"# %s=FakeLabelValue00", mixedToken + "_TOKEN", "a value named like a credential"},
		{"# %s = FakeLabelValue00", "https://bot:FakeLabelPassw0rd@ini.example.com/token", "a value named like a credential"},
		{"export A='cap://alpha' # was %s", "ghp_" + "FakeLabelTrailer00000000000000000000", "a GitHub token"},
		{"alias deploy='DEPLOY_TOKEN=%s ./deploy.sh'", mixedToken, "a random 36-character token"},
		{"export BUILD_ID=%s", mixedToken, "a random 36-character token"},
		{"export BUILD_REF=%s", "a8f3k2m9x7q1w5e4r6t0y2u8i9o7p6", "a random 30-character token"},
		{"export SIGNATURE=%s", awsSecretKey, "an AWS secret key"},
		{"export UPLOAD_SIG=%s", "Ab3d/Ef6hIj9lMn2pQr5tUv8xYz01/AbCdEf6h+Ij9l", "a 43-character base64 key"},
		{"export BLOB=%s", "c2VjcmV0LWtleS1nb2VzLWhlcmUtZm9yLXRoZS1kZW1vIQ==", "48 characters of base64 data"},
		{"export DB_CONN='%s'", "Xk9#mZ2!vLp7@wRt4%yNb8&cFj1^qD", "30 characters mixing letters, digits and symbols"},
		{"export OTEL_EXPORTER_OTLP_HEADERS='%s'", "x-honeycomb-dataset=checkout-service,x-honeycomb-environment=production",
			"71 characters mixing letters and symbols"},
	} {
		rc := write(t, t.TempDir(), ".zshrc", fmt.Sprintf(tc.line, tc.value)+"\n")
		r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc}, nil)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if strings.Contains(printed(r), tc.value) {
			t.Errorf("the report for %s printed its value", tc.label)
			continue
		}
		if out := r.Render(doctor.Format{Home: filepath.Dir(rc)}); !strings.Contains(out, "  "+tc.label+"\n") {
			t.Errorf("the report does not say %q:\n%s", tc.label, out)
		}
	}
}

// Nearby lines that hold text the same way are listed as one range, so a run of
// old keys in comments reads as one entry. Each line still counts, and a range
// spans no line listed apart, so marking each line of a range marks no line of
// another entry. Only values that may be credentials are advised to be marked, a
// range of them line by line: what holds a credential of a known shape is removed
// by hand.
func TestNearbyLinesOfOneKindAreListedAsOneRange(t *testing.T) {
	const keyID = "AKIA" + "IOSFODNN7EXAMPLE"
	rc := write(t, t.TempDir(), ".zshrc", "# prod: "+keyID+" "+awsSecretKey+"\n"+
		"# rotated monthly\n"+
		"# staging: "+keyID+" "+awsSecretKey+"\n"+
		"# dev: "+keyID+" "+awsSecretKey+"\n"+
		"alias gh='GITHUB_TOKEN="+githubToken+" gh'\n"+
		"# "+hex32+"\n"+
		"# was "+hex32+"\n"+
		"\n\n\n"+
		"# sandbox: "+keyID+" "+awsSecretKey+"\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Unmovable) != 7 {
		t.Errorf("Unmovable = %+v, want each line", r.Unmovable)
	}
	if got := strings.Join(r.Problems(), "; "); got != "5 credential(s) in plaintext" {
		t.Errorf("Problems() = %q", got)
	}
	out := printed(r)
	for _, want := range []string{
		"✗ 5 credential(s) in plaintext " +
			rc + ":1-4 edit 3 comment lines AWS access key IDs and AWS secret keys " +
			rc + ":5 edit alias a GitHub token " +
			rc + ":11 edit comment an AWS access key ID and an AWS secret key " +
			"To fix each: edit remove it by hand in an editor (in a range, every line) Then rotate",
		"! 2 value(s) that may be credentials " +
			rc + ":6-7 edit 2 comment lines runs of 32 hex characters " +
			"If one is a credential: edit remove it by hand in an editor (in a range, each line that is one) Rotate",
		"If one holds no secret, end its line with # " + migrate.IgnoreMarker + " yourself, marking each line of a range,",
	} {
		if !strings.Contains(flat(out), want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(flat(out), "marking each line of a range"); n != 1 {
		t.Errorf("the report advises marking each line of a range %d times, want once, for the values that may be credentials:\n%s", n, out)
	}
	if n := strings.Count(out, migrate.IgnoreMarker); n != 1 {
		t.Errorf("the report advises marking lines %d times, want once, for the values that may be credentials:\n%s", n, out)
	}
	for _, value := range []string{keyID, awsSecretKey, hex32, githubToken} {
		if strings.Contains(out, value) {
			t.Errorf("the report printed a value:\n%s", out)
		}
	}
}

// Commented-out pairs of an AWS key ID, which has a known shape, and its secret
// key, which only may be a credential, are one range, listed with the
// credentials, and each of its lines counts as one, in the heading and in what
// fails doctor alike. A range holding a credential of a known shape is removed by
// hand and never marked, as marking each of its lines would hide the credential
// too, and the advice to rotate follows the list once.
func TestARangeHoldingACredentialIsListedWithTheCredentials(t *testing.T) {
	const keyID = "AKIA" + "IOSFODNN7EXAMPLE"
	var content strings.Builder
	for range 3 {
		content.WriteString("# export AWS_ACCESS_KEY_ID=" + keyID + "\n# export AWS_SECRET_ACCESS_KEY=" + awsSecretKey + "\n\n\n")
	}
	rc := write(t, t.TempDir(), ".zshrc", content.String())

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(r.Problems(), "; "); got != "6 credential(s) in plaintext" {
		t.Errorf("Problems() = %q, want each line of the range, as the heading counts them", got)
	}
	out := r.Render(doctor.Format{})
	want := "✗ 6 credential(s) in plaintext " + rc + ":1-10 edit 6 comment lines AWS access key IDs and AWS secret keys " +
		"To fix each: edit remove it by hand in an editor (in a range, every line) Then rotate "
	if !strings.Contains(flat(out), want) {
		t.Errorf("the report does not list the pairs as one range of credentials:\n%s", out)
	}
	if n := strings.Count(out, "rotate"); n != 1 {
		t.Errorf("the report advises rotating %d times, want once:\n%s", n, out)
	}
	if strings.Contains(out, "may be credentials") || strings.Contains(out, migrate.IgnoreMarker) {
		t.Errorf("the report lists the secret keys apart, or advises marking the range:\n%s", out)
	}
	for _, value := range []string{keyID, awsSecretKey} {
		if strings.Contains(out, value) {
			t.Errorf("the report printed a value:\n%s", out)
		}
	}
}

// Nothing holding a credential of a known shape is advised to be marked as holding
// no secret, a line alone or a range, so no such advice follows a range of them.
func TestNothingHoldingACredentialIsAdvisedToBeMarked(t *testing.T) {
	const keyID = "AKIA" + "IOSFODNN7EXAMPLE"
	rc := write(t, t.TempDir(), ".zshrc", "export GITHUB_TOKEN="+githubToken+"\n\n\n\n"+
		"# export AWS_ACCESS_KEY_ID="+keyID+"\n# export AWS_SECRET_ACCESS_KEY="+awsSecretKey+"\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := printed(r)
	if !strings.Contains(out, "2 comment lines") {
		t.Fatalf("the report does not list the pair as one range:\n%s", out)
	}
	if strings.Contains(out, migrate.IgnoreMarker) || strings.Contains(strings.ToLower(out), "marking") {
		t.Errorf("the report advises marking a line holding a credential:\n%s", out)
	}
}

// A range says what its lines hold by kind, each once, in the plural where it is
// there more than once: a value named like a credential is the kind of what in it
// looks random, and a kind that lists words of its own comes last, so the list's
// and is the one before it.
func TestARangeNamesEachKindItHoldsOnce(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "# export SESSION_TOKEN="+hex32+"\n"+
		"# "+hex32+"\n"+
		"# export API_TOKEN="+mixedToken+"\n"+
		"# export DB_CONN='Xk9#mZ2!vLp7@wRt4%yNb8&cFj1^qD'\n"+
		"# export GITHUB_TOKEN="+githubToken+"\n"+
		"\n\n\n"+
		"# export DB_PASSWORD=correct-horse-battery-staple\n"+
		"# export REDIS_PASSWORD=correct-horse-battery-staple\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	for start, want := range map[string]string{
		rc + ":1-5 ": rc + ":1-5 edit 5 comment lines runs of 32 hex characters, a random 36-character token, a GitHub token and " +
			"30 characters mixing letters, digits and symbols",
		rc + ":9-10 ": rc + ":9-10 edit 2 comment lines values named like credentials",
	} {
		if got := row(out, start); got != want {
			t.Errorf("the row reads %q, want %q:\n%s", got, want, out)
		}
	}
}

// A kind a range holds in several lengths is named once, without them, so
// passwords of different lengths read as one kind.
func TestARangeNamesAKindOfSeveralLengthsWithoutThem(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "# export API_TOKEN="+mixedToken+"\n"+
		"# export APP_TOKEN="+mixedToken[:30]+"\n"+
		"# "+hex32+"\n"+
		"# was "+hex32+"0a1b2c3d\n"+
		"# export DB_CONN='Xk9#mZ2!vLp7@wRt4%yNb8&cFj1^qD'\n"+
		"# export LEDGER_CONN='Xk9#mZ2!vLp7@wRt4%yNb8&c'\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := rc + ":1-6 edit 6 comment lines random tokens, runs of hex characters and values mixing letters, digits and symbols"
	if out := r.Render(doctor.Format{}); row(out, rc+":1-6 ") != want {
		t.Errorf("the report lacks %q:\n%s", want, out)
	}
}

// Marking each line of a range, as the advice says, must not hide a line listed
// apart: a range ends at a line held another way, or at an assignment.
func TestARangeSpansNoLineListedApart(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "# export GITHUB_TOKEN="+githubToken+"\n"+
		"# old key "+mixedToken+"\n"+
		"alias gh='GITHUB_TOKEN="+githubToken+" gh'\n"+
		"# backup "+mixedToken+"\n"+
		"export GITHUB_TOKEN="+githubToken+"\n"+
		"# spare "+mixedToken+"\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	entry := regexp.MustCompile(regexp.QuoteMeta(rc) + `:([0-9]+)(?:-([0-9]+))?\s`)
	var spans [][2]int
	for _, m := range entry.FindAllStringSubmatch(out, -1) {
		first, _ := strconv.Atoi(m[1])
		last := first
		if m[2] != "" {
			last, _ = strconv.Atoi(m[2])
		}
		spans = append(spans, [2]int{first, last})
	}
	if len(spans) != 5 {
		t.Errorf("entries %v, want lines 1-2 as one and each of the other 4 alone:\n%s", spans, out)
	}
	for i, a := range spans {
		for j, b := range spans {
			if i != j && b[0] >= a[0] && b[0] <= a[1] {
				t.Errorf("the entry for lines %d-%d spans the one for line %d:\n%s", a[0], a[1], b[0], out)
			}
		}
	}
}

// A comment beside a value that is listed is listed alone, in no range, after the
// value, and is removed by hand whatever it holds. Marking its line would leave
// the value alone too, so the values that may be credentials say a line listed
// twice is marked only once neither holds a secret. The credentials never speak of
// marking.
func TestACommentBesideAListedValueIsListedAlone(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "export A='cap://alpha' # was "+hex32+"\n"+
		"export GITHUB_TOKEN="+githubToken+" # was "+hex32+"\n"+
		"export C='cap://gamma' # was "+"ghp_"+"FakeRangeTrailer00000000000000000000\n"+
		"export BUILD_ID="+mixedToken+" # was "+"ghp_"+"FakeRangeTrailer00000000000000000000\n"+
		"export B='cap://beta' # was "+hex32+"\n")

	r, err := doctor.Run(store(t, map[string]string{"alpha": "", "beta": "", "gamma": ""}), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	sure, unsure := section(out, "✗ "), section(out, "! ")
	for _, want := range []string{
		rc + ":2 migrate GITHUB_TOKEN a GitHub token " + rc + ":3 edit trailer a GitHub token " + rc + ":4 edit trailer a GitHub token " +
			"To fix each: migrate move it with keyward migrate " + rc + " (preview with --dry-run), or store it with keyward add NAME and set the variable to 'cap://NAME' " +
			"edit remove it by hand in an editor e.g. keyward add github-token and set GITHUB_TOKEN to 'cap://github-token' Then rotate",
	} {
		if !strings.Contains(flat(sure), want) {
			t.Errorf("the credentials lack %q:\n%s", want, sure)
		}
	}
	for _, want := range []string{
		rc + ":1 edit trailer 32 hex characters " + rc + ":2 edit trailer 32 hex characters " + rc + ":4 add BUILD_ID a random 36-character token " +
			rc + ":5 edit trailer 32 hex characters " +
			"If one is a credential: add store it with keyward add NAME and set the variable to 'cap://NAME'; migrate moves only values it is sure of " +
			"edit remove it by hand in an editor e.g. keyward add build-id and set BUILD_ID to 'cap://build-id' Rotate",
		listedTwice,
	} {
		if !strings.Contains(flat(unsure), want) {
			t.Errorf("the values lack %q:\n%s", want, unsure)
		}
	}
	if strings.Contains(strings.ToLower(sure), "marking") || strings.Contains(sure, migrate.IgnoreMarker) {
		t.Errorf("the report advises marking a line that fails doctor:\n%s", out)
	}
}

// Only a comment beside a listed value fails doctor here. Marking the line, for the
// comment or the value, would hide both, so neither list advises it, and the
// values say why.
func TestNothingAdvisesMarkingACommentBesideAListedValue(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "export BUILD_ID="+mixedToken+" # was "+githubToken+"\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	if !strings.Contains(out, "✗ 1 credential(s) in plaintext\n") || !strings.Contains(row(section(out, "! "), rc+":1 "), " add BUILD_ID ") {
		t.Fatalf("the report does not list the line's comment and value:\n%s", out)
	}
	if strings.Contains(out, migrate.IgnoreMarker) {
		t.Errorf("the report advises marking a line whose comment fails doctor:\n%s", out)
	}
	if !strings.Contains(flat(section(out, "! ")), "migrate moves only values it is sure of e.g. keyward add build-id and set BUILD_ID to 'cap://build-id' Rotate each one that is a credential, "+
		"and store its new value with keyward add --force NAME. "+listedTwice) {
		t.Errorf("the advice for the value does not say to mark the line only once neither holds a secret:\n%s", out)
	}
}

// Text written in place of a credential holds none: a known prefix followed by
// one character over and over, or a template in angle brackets, whole or as a
// URL's password. doctor leaves it out, in a value, a comment or an MCP server.
func TestPlaceholdersAreLeftOut(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "export GITHUB_TOKEN="+"ghp_"+strings.Repeat("x", 36)+"\n"+
		"export STRIPE_SECRET_KEY="+"sk_test_"+strings.Repeat("x", 24)+"\n"+
		"export AWS_ACCESS_KEY_ID="+"AKIA"+strings.Repeat("X", 16)+"\n"+
		`export OPENAI_API_KEY="<your-openai-api-key>"`+"\n"+
		"export LINEAR_API_KEY='<YOUR_LINEAR_API_KEY>'\n"+
		"export ANALYTICS_DB_URL=postgres://app:<password>@db.internal:5432/analytics\n"+
		"# export SLACK_BOT_TOKEN="+"xoxb-"+strings.Repeat("x", 24)+"\n"+
		"# export DATABASE_URL='postgres://app:<password>@localhost:5432/app'\n"+
		"# postgres://app:<password>@localhost:5432/app\n")
	servers := []mcpconfig.Server{{Client: "Claude Code", Config: "/home/someone/.claude.json", Name: "linear", Command: "linear-mcp",
		Env: map[string]string{"LINEAR_API_KEY": "<your-linear-api-key>"}, Headers: map[string]string{"X-Api-Key": "<your-api-key>"}}}

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Plaintext) != 0 || len(r.Unmovable) != 0 || len(r.Literals) != 0 {
		t.Errorf("Plaintext %+v, Unmovable %+v, Literals %+v: want no placeholder listed", r.Plaintext, r.Unmovable, r.Literals)
	}
}

// Only those forms make a placeholder. Words can be a password, a URL's other
// parts can hold a key, and a scheme before a template leaves a value that can be
// a real one, so each of these is listed as before.
func TestAPlaceholdersWordsAreNoPlaceholder(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "export DB_PASSWORD=changeme-before-prod\n"+
		"export LINEAR_API_KEY=your-linear-api-key-here\n"+
		`export API_TOKEN="paste-your-token-here"`+"\n"+
		"export DATABASE_URL=postgres://app:password@localhost:5432/app\n"+
		"export BILLING_URL='postgres://app:<password>@db.internal:5432/billing?api_key=Kq7pL2xV9mN4wRt5'\n"+
		"export LEDGER_URL='postgres://app:<password>@ledger-db.internal:5432,orders-db.internal:5432/ledger'\n"+
		`export AUTH_HEADER="Bearer <your-token>"`+"\n"+
		"export GITHUB_TOKEN="+"ghp_"+strings.Repeat("x", 35)+"y\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Plaintext) != 8 {
		t.Errorf("Plaintext = %+v, want each line", r.Plaintext)
	}
}

// eyJ starts any JSON in base64, so only a JWT's three parts fail doctor. migrate
// moves either, as it moves any value that starts with a credential's prefix.
func TestOnlyAJWTOfTheValuesStartingEyJFailsDoctor(t *testing.T) {
	rc := write(t, t.TempDir(), ".zshrc", "export ID_TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl\n"+
		"export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(r.Problems(), "; "); got != "1 credential(s) in plaintext" {
		t.Errorf("Problems() = %q", got)
	}
	out := r.Render(doctor.Format{})
	if want := "! 1 value(s) that may be credentials " + rc + ":2 migrate SPLUNK_MCP_TOKEN base64-encoded JSON " +
		"If one is a credential: migrate move it with keyward migrate " + rc + " (preview"; !strings.Contains(flat(out), want) {
		t.Errorf("the report lacks %q:\n%s", want, out)
	}
}

// migrate moves a value only its name suggests, but never one only randomness
// marks, so the advice for that one is to store it and set the variable by hand.
func TestTheAdviceForAPossibleCredentialSaysHowToMoveIt(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export MY_SERVICE_TOKEN=correct-horse-battery-staple-9271\nexport BUILD_ID=Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	for _, want := range []string{
		rc + ":1 migrate MY_SERVICE_TOKEN the variable name suggests a credential " + rc + ":2 add BUILD_ID a random 36-character token " +
			"If one is a credential: migrate move it with keyward migrate " + rc + " (preview with --dry-run), or store it with keyward add NAME and set the variable to 'cap://NAME' " +
			"add store it with keyward add NAME and set the variable to 'cap://NAME'; migrate moves only values it is sure of " +
			"e.g. keyward add my-service-token and set MY_SERVICE_TOKEN to 'cap://my-service-token' Rotate",
	} {
		if !strings.Contains(flat(out), want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
}

// keyward:ignore in a line's comment leaves the line out, whatever it holds.
func TestIgnoreMarkerLeavesALineOut(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export GITHUB_TOKEN="+githubToken+" # "+migrate.IgnoreMarker+"\n"+
		"# AWS's documented example key: AKIAIOSFODNN7EXAMPLE # "+migrate.IgnoreMarker+"\n"+
		"export GIT_AUTHOR_EMAIL=someone@example.com\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Plaintext) != 1 || r.Plaintext[0].Name != "GIT_AUTHOR_EMAIL" || len(r.Unmovable) != 0 {
		t.Errorf("Plaintext = %+v, Unmovable = %+v, want only the unmarked line", r.Plaintext, r.Unmovable)
	}
}

// Detect runs on each assignment directly. A migration plan refuses the whole file
// when two names would share one reference, which would hide both credentials.
func TestPlaintextIsFoundInAFileMigrationRefuses(t *testing.T) {
	dir := t.TempDir()
	content := "export GITHUB_TOKEN=" + githubToken + "\nexport github_token=" + githubToken + "\n"
	rc := write(t, dir, ".zshrc", content)
	if _, err := migrate.NewPlan(rc, []byte(content)); err == nil {
		t.Fatal("NewPlan accepted names that collide; this test needs a file it refuses")
	}

	r, err := doctor.Run(vault.NewMemory(), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Plaintext) != 2 {
		t.Errorf("Plaintext = %+v, want both lines", r.Plaintext)
	}
}

// MCP configs are checked through their parsed servers, so a credential there is
// named by client, config, server and field, and never shown.
func TestCredentialsInMCPServersAreReported(t *testing.T) {
	servers := []mcpconfig.Server{{Client: "Claude Code", Config: "/home/someone/.claude.json", Name: "github",
		Env: map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": githubToken, "API_KEY": namedValue}}}

	r, err := doctor.Run(vault.NewMemory(), nil, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(r.Problems(), "; "); got != "1 credential(s) in plaintext" {
		t.Errorf("Problems() = %q", got)
	}
	out := printed(r)
	if got, want := row(out, "server github, env.GITHUB_PERSONAL_ACCESS_TOKEN"), "/home/someone/.claude.json mcp Claude Code server github, env.GITHUB_PERSONAL_ACCESS_TOKEN a GitHub token "+
		"store it with keyward add NAME, write ${GITHUB_PERSONAL_ACCESS_TOKEN} in its place, add export GITHUB_PERSONAL_ACCESS_TOKEN='cap://NAME' to ~/.zshrc, and run keyward mcp wrap"; got != want {
		t.Errorf("the row reads %q, want %q:\n%s", got, want, out)
	}
	if !strings.Contains(section(out, "! 1 value(s) that may be credentials"), "Claude Code server github, env.API_KEY\n") {
		t.Errorf("the report does not list env.API_KEY as a value that may be a credential:\n%s", out)
	}
	// Each server's fix is under its row, which leaves a legend nothing to list.
	if strings.Contains(out, "To fix each:") || strings.Contains(out, "If one is a credential:") {
		t.Errorf("a legend lists no fix:\n%s", out)
	}
	for _, value := range []string{githubToken, namedValue} {
		if strings.Contains(out, value) {
			t.Errorf("the report printed a value:\n%s", out)
		}
	}
}

// Changed back by unwrap or uninstall, a server reads each reference in its env
// from its client's environment, from a variable of the same name. So the advice
// for a credential in env routes it through that variable, set in ~/.zshrc, which
// uninstall then sets to the value, in each client's own way.
func TestTheAdviceForACredentialInEnvUsesAVariableOfTheSameName(t *testing.T) {
	for client, want := range map[string]string{
		"Claude Code": "store it with keyward add NAME, write ${DD_APP_KEY} in its place, add export DD_APP_KEY='cap://NAME' to ~/.zshrc, and run keyward mcp wrap",
		"Cursor":      "store it with keyward add NAME, write ${env:DD_APP_KEY} in its place, add export DD_APP_KEY='cap://NAME' to ~/.zshrc, and run keyward mcp wrap",
		"Codex":       "store it with keyward add NAME, remove it and add \"DD_APP_KEY\" to env_vars, add export DD_APP_KEY='cap://NAME' to ~/.zshrc, and run keyward mcp wrap",
	} {
		servers := []mcpconfig.Server{{Client: client, Config: "/home/someone/config", Name: "datadog", Env: map[string]string{"DD_APP_KEY": githubToken}}}
		r, err := doctor.Run(vault.NewMemory(), nil, servers)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out := r.Render(doctor.Format{}); !strings.HasSuffix(row(out, "server datadog, env.DD_APP_KEY"), " a GitHub token "+want) {
			t.Errorf("%s: the report lacks %q:\n%s", client, want, out)
		}
	}
}

// mcp-remote puts a remote server's URL in its command line, so wrap puts a
// migrated secret there only if given --allow-command-line. The advice for a
// credential in a URL is to send it in a header, if the server takes it there, and
// otherwise says what --allow-command-line exposes.
func TestTheAdviceForACredentialInAURLSaysToSendItInAHeader(t *testing.T) {
	const otherwise = ", or else write ${VAR} in its place, which wrap puts in mcp-remote's command line and log only if given --allow-command-line; then run keyward mcp wrap"
	for client, want := range map[string]string{
		"Claude Code": "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and send it in a header as ${VAR}, if the server takes it there" + otherwise,
		"Codex":       "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and send it in a header with env_http_headers = { \"HEADER\" = \"VAR\" }, if the server takes it there" + otherwise,
		// mcp-remote takes the URL as an argument, where Copilot fills a ${VAR} in
		// itself, so there is no otherwise.
		"Copilot CLI": "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and send it in a header as ${VAR}, if the server takes it there, " +
			"as keyward starts a remote server through mcp-remote, which takes the URL as an argument, where Copilot CLI fills in a ${VAR} itself; then run keyward mcp wrap",
	} {
		servers := []mcpconfig.Server{{Client: client, Config: "/home/someone/config", Name: "exa", URL: "https://mcp.example.com/mcp?token=" + githubToken}}
		r, err := doctor.Run(vault.NewMemory(), nil, servers)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out := r.Render(doctor.Format{}); !strings.Contains(out, "server exa, url\n") || !strings.HasSuffix(row(out, "server exa, url"), " "+want) {
			t.Errorf("%s: the report lacks %q:\n%s", client, want, out)
		}
	}
}

// keyward run refuses a server that passes a secret as an argument, unless given
// --allow-command-line, so the advice for a credential in a server's args is to
// pass it in env, if the server reads it from there, and otherwise says that
// wrap puts ${VAR} there in its command line only if given the option, as
// mcp-remote fills in one in a --header itself.
func TestTheAdviceForACredentialInArgsSaysToPassItInEnv(t *testing.T) {
	const otherwise = ", if the server reads it from there, or else write ${VAR} in its place, which wrap puts in the server's command line only if given " +
		"--allow-command-line, unless it is in an mcp-remote --header; then run keyward mcp wrap"
	for client, want := range map[string]string{
		"Claude Code": "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and pass it in env as VAR" + otherwise,
		"Codex":       "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and pass it with env_vars = [\"VAR\"]" + otherwise,
		"Copilot CLI": "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and pass it in env as VAR, if the server reads it from there, as Copilot CLI fills in a ${VAR} in its command itself; then run keyward mcp wrap",
	} {
		servers := []mcpconfig.Server{{Client: client, Config: "/home/someone/config", Name: "slack", Command: "npx", Args: []string{"-y", "slack-mcp", "--token", githubToken}}}
		r, err := doctor.Run(vault.NewMemory(), nil, servers)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out := r.Render(doctor.Format{}); !strings.Contains(out, "server slack, args[3]\n") || !strings.HasSuffix(row(out, "server slack, args[3]"), " "+want) {
			t.Errorf("%s: the report lacks %q:\n%s", client, want, out)
		}
	}
}

// Copilot CLI, once installed, starts the servers in a project's .mcp.json too, so
// the advice for a credential in one's URL or args is the advice for Copilot's.
func TestTheAdviceForAProjectsServerIsCopilotsOnceItIsInstalled(t *testing.T) {
	home, workdir := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".copilot"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workdir, ".mcp.json"), []byte(`{"mcpServers": {
  "slack": {"command": "npx", "args": ["-y", "slack-mcp", "--token", "`+githubToken+`"]},
  "exa": {"type": "http", "url": "https://mcp.example.com/mcp?token=`+githubToken+`"}
}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, errs := mcpconfig.Load(home, workdir)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	r, err := doctor.Run(vault.NewMemory(), nil, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	const shared = "Copilot CLI, which starts a project's .mcp.json servers too,"
	out := r.Render(doctor.Format{})
	for start, want := range map[string]string{
		"server slack, args[3]": "and pass it in env as VAR, if the server reads it from there, as " + shared + " fills in a ${VAR} in its command itself; then run keyward mcp wrap in " + workdir,
		"server exa, url": "and send it in a header as ${VAR}, if the server takes it there, as keyward starts a remote server through mcp-remote, which takes the URL as an argument, " +
			"where " + shared + " fills in a ${VAR} itself; then run keyward mcp wrap in " + workdir,
	} {
		if !strings.HasSuffix(row(out, start), " "+want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
}

// wrap changes a Claude Code project's server only in the project's folder, so the
// advice for a credential in one names the folder. Where the folder no longer
// exists, as a removed worktree's, it says to remove the server by hand instead.
func TestTheAdviceForACredentialInAProjectsServerNamesWhereToChangeIt(t *testing.T) {
	config := filepath.Join(t.TempDir(), ".claude.json")
	project, removed := t.TempDir(), filepath.Join(t.TempDir(), "removed-worktree")
	var servers []mcpconfig.Server
	for _, dir := range []string{project, removed} {
		servers = append(servers, mcpconfig.Server{Client: "Claude Code", Config: config + " (project " + dir + ")", Name: filepath.Base(dir), Scope: "local",
			Project: dir, Env: map[string]string{"GITHUB_PERSONAL_ACCESS_TOKEN": githubToken}})
	}

	r, err := doctor.Run(vault.NewMemory(), nil, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	if want := " add export GITHUB_PERSONAL_ACCESS_TOKEN='cap://NAME' to ~/.zshrc, and run keyward mcp wrap in " + project; !strings.HasSuffix(row(out, "(project "+project+")"), want) {
		t.Errorf("the report lacks %q:\n%s", want, out)
	}
	if got, want := row(out, "server removed-worktree, "), config+" mcp Claude Code server removed-worktree, env.GITHUB_PERSONAL_ACCESS_TOKEN (project "+removed+") a GitHub token "+
		"remove the server from "+config+" by hand, with Claude Code closed, as its project's folder no longer exists"; got != want {
		t.Errorf("the row reads %q, want %q:\n%s", got, want, out)
	}
	if strings.Contains(flat(out), "wrap in "+removed) {
		t.Errorf("the report says to run wrap in a folder that is gone:\n%s", out)
	}
}

// The Codex and Claude Code configs, and any other MCP config whose servers were
// read, are checked through their servers alone. Read line by line as well, they
// would count a token twice and suggest migrating a file that belongs to its
// tool. Another config.toml, and a .mcp.json whose servers were not read, are
// still read line by line.
func TestMCPConfigsAreCheckedThroughTheirServersAlone(t *testing.T) {
	home, workdir := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	codex := write(t, filepath.Join(home, ".codex"), "config.toml", `[mcp_servers.github]
url="https://api.example.com/mcp/"
bearer_token_env_var="GITHUB_PERSONAL_ACCESS_TOKEN"

[mcp_servers.pd]
command="uvx"

[mcp_servers.pd.env]
PD_TOKEN="`+githubToken+`"
PD_FALLBACK_TOKEN = "`+githubToken+`"
`)
	mcp := `{"mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": "` + githubToken + `"}}}}`
	project := write(t, workdir, ".mcp.json", mcp)
	elsewhere := write(t, t.TempDir(), ".mcp.json", mcp)
	other := write(t, home, "config.toml", `API_TOKEN="`+githubToken+`"`+"\n")
	servers, errs := mcpconfig.Load(home, workdir)
	if len(errs) != 0 {
		t.Fatal(errs)
	}

	r, err := doctor.Run(vault.NewMemory(), []string{codex, project, elsewhere, other}, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Literals) != 3 || len(r.Plaintext) != 1 || r.Plaintext[0].File != other ||
		len(r.Unmovable) != 1 || r.Unmovable[0].File != elsewhere {
		t.Errorf("Literals %+v, Plaintext %+v, Unmovable %+v: want the servers' tokens, and the other files'", r.Literals, r.Plaintext, r.Unmovable)
	}
	if out := r.Render(doctor.Format{}); strings.Contains(flat(out), "keyward migrate "+codex) || !strings.Contains(flat(out), "keyward migrate "+other) {
		t.Errorf("the report suggests migrating Codex's config:\n%s", out)
	}
}

// A value that may be a credential in an MCP config gets the advice for one there,
// not for a shell or .env file: migrate must not rewrite the tool's own config.
// Outside env, a reference is read through a variable set in a shell file.
func TestTheAdviceForPossibleCredentialsSaysWhichFilesMigrateIsFor(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".claude.json", `{"mcpServers": {"team": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"X-Team": "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i"}}}}`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}

	r, err := doctor.Run(vault.NewMemory(), nil, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	if !strings.Contains(out, "! 1 value(s) that may be credentials") || !strings.Contains(out, "Claude Code server team, headers.X-Team") {
		t.Fatalf("this test needs the header listed as a value that may be a credential:\n%s", out)
	}
	if want := " if it is one, store it with keyward add NAME, write ${VAR} in its place, add export VAR='cap://NAME' to ~/.zshrc, and run keyward mcp wrap"; !strings.HasSuffix(row(out, "server team, headers.X-Team"), want) ||
		strings.Contains(out, "keyward migrate") {
		t.Errorf("the advice is not for an MCP config, or sends it to migrate:\n%s", out)
	}
}

// Codex fills no variable in http_headers, so the advice for a value there is to
// move it to env_http_headers, which reads a variable, or for a Bearer token in
// Authorization, to bearer_token_env_var, which adds the Bearer itself.
func TestTheAdviceForACodexHTTPHeaderMovesItToAVariable(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".codex"), "config.toml", `[mcp_servers.team]
url = "https://mcp.example.com/mcp"
http_headers = { "X-Team" = "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i", Authorization = "Bearer `+githubToken+`" }
`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}

	r, err := doctor.Run(vault.NewMemory(), nil, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.Render(doctor.Format{})
	for what, want := range map[string]string{
		"Codex server team, http_headers.X-Team": " if it is one, store it with keyward add NAME, move it to env_http_headers = { \"X-Team\" = \"VAR\" }, " +
			"add export VAR='cap://NAME' to ~/.zshrc, and run keyward mcp wrap",
		"Codex server team, http_headers.Authorization": " store it with keyward add NAME, move it to env_http_headers = { \"Authorization\" = \"VAR\" }, " +
			"or for a Bearer token, store the token alone and use bearer_token_env_var = \"VAR\"; add export VAR='cap://NAME' to ~/.zshrc, and run keyward mcp wrap",
	} {
		if !strings.Contains(out, what+"\n") || !strings.HasSuffix(row(out, what), want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "in its place") {
		t.Errorf("the advice says to write a variable where Codex fills none:\n%s", out)
	}
}

// Naming a default file again, as in keyward doctor ~/.zshrc, or by a relative
// path, as in keyward doctor .env, must not count what it holds twice.
func TestAFileNamedTwiceIsReadOnce(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export GITHUB_TOKEN="+githubToken+"\nexport T='cap://absent'\n")
	t.Chdir(dir)

	r, err := doctor.Run(vault.NewMemory(), []string{rc, rc, ".zshrc"}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Scanned) != 1 || len(r.Plaintext) != 1 || len(r.Dangling) != 1 {
		t.Errorf("Scanned %v, Plaintext %v, Dangling %v: want each once", r.Scanned, r.Plaintext, r.Dangling)
	}
}

// ===========================================================================
// Classifying stored secrets
// ===========================================================================

// The only case keyward can call orphaned with confidence: provenance names a file
// that was actually scanned, and that file no longer mentions it.
func TestOrphanedRequiresAScannedSourceThatNoLongerReferencesIt(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export KEPT='cap://kept'\n")

	s := store(t, map[string]string{
		"kept":    rc + ":1",
		"removed": rc + ":2", // the line it came from is gone
	})

	r, err := doctor.Run(s, []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := names(r.Orphaned); strings.Join(got, ",") != "removed" {
		t.Errorf("Orphaned = %v, want [removed]", got)
	}
	if got := strings.Join(r.Referenced, ","); got != "kept" {
		t.Errorf("Referenced = %v, want [kept]", r.Referenced)
	}
	// An orphan is informational, not a failure.
	if p := r.Problems(); len(p) > 0 {
		t.Errorf("Problems() = %v for an orphan alone", p)
	}
	if out := r.Render(doctor.Format{}); !strings.HasPrefix(row(out, "removed "), "removed came from ") || !strings.Contains(row(out, "removed "), " keyward rm removed") {
		t.Errorf("the report does not offer the removal command:\n%s", out)
	}
}

// Absence of a reference is only evidence if the file was actually read. These three
// cases all look identical to a naive scan and none may be called orphaned.
func TestUnknownRatherThanOrphaned(t *testing.T) {
	dir := t.TempDir()
	scanned := write(t, dir, ".zshrc", "export X='cap://irrelevant'\n")
	unscanned := write(t, dir, ".zshenv", "export Y='cap://from-unscanned'\n")

	s := store(t, map[string]string{
		"irrelevant":     scanned + ":1",
		"from-unscanned": unscanned + ":1",                  // real source, never looked at
		"from-deleted":   filepath.Join(dir, "gone") + ":1", // source no longer exists
		"by-hand":        "",                                // no provenance at all
	})

	// Deliberately scan only .zshrc.
	r, err := doctor.Run(s, []string{scanned}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(r.Orphaned) != 0 {
		t.Errorf("Orphaned = %v, want none of these called orphaned", names(r.Orphaned))
	}
	got := strings.Join(names(r.Unknown), ",")
	if got != "by-hand,from-deleted,from-unscanned" {
		t.Errorf("Unknown = %v, want all three", names(r.Unknown))
	}

	// Each has to explain itself differently, or the user cannot judge them.
	details := map[string]string{}
	for _, f := range r.Unknown {
		details[f.Name] = f.Detail
	}
	if !strings.Contains(details["by-hand"], "by hand") {
		t.Errorf("by-hand detail = %q", details["by-hand"])
	}
	if !strings.Contains(details["from-deleted"], "no longer exists") {
		t.Errorf("from-deleted detail = %q", details["from-deleted"])
	}
	if !strings.Contains(details["from-unscanned"], "not scanned") {
		t.Errorf("from-unscanned detail = %q", details["from-unscanned"])
	}
}

// A secret referenced anywhere at all is healthy, even if its provenance points
// somewhere else — the value moved, which is fine.
func TestReferencedAnywhereCountsAsHealthy(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export OLD=nothing\n")
	env := write(t, dir, ".env", "TOKEN=cap://moved\n")

	s := store(t, map[string]string{"moved": rc + ":1"})

	r, err := doctor.Run(s, []string{rc, env}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(r.Referenced, ","); got != "moved" {
		t.Errorf("Referenced = %v, want [moved]", r.Referenced)
	}
	if len(r.Orphaned) != 0 {
		t.Errorf("Orphaned = %v, want none", names(r.Orphaned))
	}
}

// keyward run lowercases a reference's name, as the vault does, so a reference in
// capitals uses the secret stored in lower case: it neither dangles nor leaves that
// secret orphaned. One to a secret that is not stored is reported as written.
func TestAReferenceMatchesAStoredNameInAnyCase(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://ALPHA'\nexport GONE='cap://Gone-Key'\n")
	env := write(t, dir, ".env", "LINEAR_API_KEY=cap://Linear-API-Key\n")

	r, err := doctor.Run(store(t, map[string]string{"alpha": "", "linear-api-key": rc + ":3"}), []string{rc, env}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(r.Referenced, ","); got != "alpha,linear-api-key" || len(r.Orphaned) != 0 {
		t.Errorf("Referenced %v, Orphaned %v: want both secrets referenced", r.Referenced, names(r.Orphaned))
	}
	if len(r.Dangling) != 1 || r.Dangling[0].Name != "Gone-Key" {
		t.Errorf("Dangling = %+v, want only Gone-Key, as written", r.Dangling)
	}
}

// A server started through keyward run resolves the reference in its env, so a
// reference counts in every MCP config whose servers were read, as in a shell
// file: Cursor's, a Cursor project's, a Claude Code project's .mcp.json, and
// Codex's. Such a config is read for references alone, as its credentials are
// found through its servers.
func TestAReferenceInAnMCPConfigWhoseServersWereReadCounts(t *testing.T) {
	home, workdir, project := t.TempDir(), t.TempDir(), t.TempDir()
	rc := write(t, home, ".zshrc", "# the values are back in place of their references\n")
	server := func(ref string) string {
		return `{"mcpServers": {"linear": {"command": "keyward", "args": ["run", "--only", "LINEAR_API_KEY", "--", "linear-mcp"], "env": {"LINEAR_API_KEY": "cap://` + ref + `"}},
  "github": {"command": "gh-mcp", "env": {"GITHUB_TOKEN": "` + githubToken + `"}}}}`
	}
	configs := map[string]string{
		filepath.Join(home, ".cursor", "mcp.json"):    server("cursor"),
		filepath.Join(workdir, ".cursor", "mcp.json"): server("cursor-project"),
		filepath.Join(workdir, ".mcp.json"):           server("this-project"),
		filepath.Join(project, ".mcp.json"):           server("other-project"),
		filepath.Join(home, ".claude.json"):           `{"projects": {"` + project + `": {}}}`,
		filepath.Join(home, ".codex", "config.toml"):  "[mcp_servers.linear]\ncommand = \"keyward\"\nenv = { LINEAR_API_KEY = \"cap://codex\" }\n",
	}
	for path, content := range configs {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Dir(path), filepath.Base(path), content)
	}
	secrets := []string{"codex", "cursor", "cursor-project", "other-project", "this-project"}
	notes := map[string]string{}
	for _, name := range secrets {
		notes[name] = rc + ":1"
	}
	servers, errs := mcpconfig.LoadAll(home, workdir)
	if len(errs) != 0 {
		t.Fatal(errs)
	}

	r, err := doctor.Run(store(t, notes), doctor.DefaultPaths(home, workdir), servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Orphaned) != 0 || strings.Join(r.Referenced, ",") != strings.Join(secrets, ",") {
		t.Errorf("Orphaned %v, Referenced %v: want each secret a server's config references", names(r.Orphaned), r.Referenced)
	}
	for path := range configs {
		if !slices.Contains(r.Scanned, path) {
			t.Errorf("Scanned %v lacks %s", r.Scanned, path)
		}
	}
	if len(r.Literals) != 4 || len(r.Plaintext) != 0 || len(r.Unmovable) != 0 {
		t.Errorf("Literals %+v, Plaintext %+v, Unmovable %+v: want each token once, through its server", r.Literals, r.Plaintext, r.Unmovable)
	}
}

// ===========================================================================
// Coverage honesty
// ===========================================================================

// The report has to say what it looked at. Without that, "unreferenced" reads as
// "unused", which is the inference that gets a credential deleted.
func TestReportStatesItsCoverage(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://alpha'\n")
	missing := filepath.Join(dir, ".bashrc")

	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc, missing}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if strings.Join(r.Scanned, ",") != rc {
		t.Errorf("Scanned = %v, want just %s", r.Scanned, rc)
	}
	if strings.Join(r.Absent, ",") != missing {
		t.Errorf("Absent = %v, want %s", r.Absent, missing)
	}
	out := r.Summary(doctor.Format{}, nil, nil)
	if !strings.Contains(out, "read "+rc+"\n") {
		t.Errorf("the report does not list the file it scanned:\n%s", out)
	}
	if !strings.Contains(out, "not read "+missing+"\n") {
		t.Errorf("the report does not mention the file it could not read:\n%s", out)
	}
}

// Provenance is "path:line", and a macOS path may itself contain a colon. Only a
// trailing all-digit segment is the line number.
func TestProvenanceWithAwkwardPaths(t *testing.T) {
	dir := t.TempDir()
	odd := write(t, dir, "weird:name.zshrc", "# nothing here\n")
	plain := write(t, dir, ".zshrc", "# nothing here either\n")

	s := store(t, map[string]string{
		"from-colon-path": odd + ":3",
		"no-line-number":  plain, // a note with no line suffix at all
	})

	r, err := doctor.Run(s, []string{odd, plain}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Both sources were scanned and reference nothing, so both are provable orphans.
	if got := strings.Join(names(r.Orphaned), ","); got != "from-colon-path,no-line-number" {
		t.Errorf("Orphaned = %v, want both recognised", names(r.Orphaned))
	}
}

// Occurrences are ordered by file then line, so the report reads in the order a
// person would work through it.
func TestDanglingIsOrderedByFileThenLine(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.env", "X=cap://one\n\nY=cap://two\n")
	b := write(t, dir, "b.env", "Z=cap://three\n")

	r, err := doctor.Run(vault.NewMemory(), []string{b, a}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got []string
	for _, d := range r.Dangling {
		got = append(got, fmt.Sprintf("%s:%d", filepath.Base(d.File), d.Line))
	}
	want := "a.env:1,a.env:3,b.env:1"
	if strings.Join(got, ",") != want {
		t.Errorf("Dangling order = %v, want %s", got, want)
	}
}

// Every section has to actually render, or a problem could be detected and never
// shown.
func TestReportRendersEverySection(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "A=cap://absent\nB=cap://-malformed\nC=cap://present\n"+
		"D="+githubToken+"\nGIT_AUTHOR_EMAIL=someone@example.com\n")
	missing := filepath.Join(dir, "gone.env")

	s := store(t, map[string]string{
		"present": rc + ":3",
		"orphan":  rc + ":9",
		"by-hand": "",
	})

	r, err := doctor.Run(s, []string{rc, missing}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The checklist repeats most headings, so each section is looked for in the
	// sections alone.
	out := r.Render(doctor.Format{Home: dir})
	for _, want := range []string{
		"✗ 1 reference(s) point at secrets that are not in the vault\n  ~/.zshrc:1  cap://absent ",
		"✗ 1 malformed reference(s), which will fail when used\n  ~/.zshrc:2  cap://-malformed\n",
		"✗ 1 credential(s) in plaintext\n  ~/.zshrc:4 ",
		"! 1 value(s) that may be credentials\n  ~/.zshrc:5 ",
		"! 1 secret(s) whose source no longer references them\n  orphan ",
		"! 1 secret(s) nothing scanned refers to, which may still be in use\n  by-hand ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report omits the section %q:\n%s", want, out)
		}
	}
	out = r.Summary(doctor.Format{}, r.Checks(), nil)
	for _, want := range []string{"not read " + missing + "\n", "1 secret(s) stored and referenced"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary omits %q:\n%s", want, out)
		}
	}
}

// The default set has to be absolute paths under the given home, so a test never
// reads the developer's own configuration and the command works from any directory.
func TestDefaultPaths(t *testing.T) {
	paths := doctor.DefaultPaths("/home/someone", "/work/project")

	var sawRC, sawEnv, sawCodex bool
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			t.Errorf("%q is not absolute", p)
		}
		switch p {
		case "/home/someone/.zshrc":
			sawRC = true
		case "/work/project/.env":
			sawEnv = true
		case "/home/someone/.codex/config.toml":
			sawCodex = true
		}
	}
	if !sawRC || !sawEnv || !sawCodex {
		t.Errorf("DefaultPaths missing an expected entry: %v", paths)
	}

	// No working directory means no .env to look for, not a path rooted at "/".
	for _, p := range doctor.DefaultPaths("/home/someone", "") {
		if strings.HasSuffix(p, "/.env") {
			t.Errorf("DefaultPaths invented %q with no working directory", p)
		}
	}
}

func TestStoreFailureIsReported(t *testing.T) {
	if _, err := doctor.Run(brokenStore{}, nil, nil); err == nil {
		t.Error("Run succeeded against an unreadable vault")
	}
}

type brokenStore struct{ vault.Store }

func (brokenStore) Entries() ([]vault.Entry, error) {
	return nil, errors.New("keychain unavailable")
}

// A clean machine should say so plainly rather than printing empty sections.
func TestCleanReport(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://alpha'\n")

	r, err := doctor.Run(store(t, map[string]string{"alpha": rc + ":1"}), []string{rc}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if p := r.Problems(); len(p) > 0 {
		t.Errorf("Problems() = %v for a healthy setup", p)
	}
	if out := r.Render(doctor.Format{}); out != "" {
		t.Errorf("a clean report lists something:\n%s", out)
	}
	if out := (doctor.Format{}).Verdict(r.Checks(), r.Problems()); out != "✓ No problems found.\n" {
		t.Errorf("a clean report ends %q", out)
	}
}

// Duplicate references to one name are normal — the same token in a shell file and
// an MCP config — and must not be double reported.
func TestDuplicateReferencesCountOnce(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, ".zshrc", "export T='cap://shared'\n")
	b := write(t, dir, "mcp.json", `{"env":{"T":"cap://shared"}}`)

	r, err := doctor.Run(store(t, map[string]string{"shared": ""}), []string{a, b}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.Join(r.Referenced, ","); got != "shared" {
		t.Errorf("Referenced = %v, want one entry", r.Referenced)
	}
}

// Every dangling occurrence is worth reporting, so each place needing a fix is
// visible rather than just the first.
func TestDanglingReportedPerOccurrence(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, ".zshrc", "export T='cap://absent'\n")
	b := write(t, dir, "mcp.json", `{"env":{"T":"cap://absent"}}`)

	r, err := doctor.Run(vault.NewMemory(), []string{a, b}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Dangling) != 2 {
		t.Errorf("Dangling = %+v, want one per occurrence", r.Dangling)
	}
}

// Uninstall uses this to name every file that would break, including ones
// outside the default paths that provenance points to.
func TestInUseCountsStoredReferencesPerFile(t *testing.T) {
	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	project := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(rc, []byte("export A='cap://a'\nexport B='cap://b'\nexport GONE='cap://gone'\n"), 0o644)
	os.WriteFile(project, []byte("C=cap://c\n"), 0o644)
	store := vault.NewMemory()
	for name, note := range map[string]string{"a": rc + ":1", "b": "", "c": project + ":1"} {
		if err := store.Put(name, vault.NewSecret([]byte("v")), note); err != nil {
			t.Fatal(err)
		}
	}
	got, err := doctor.InUse(store, []string{rc})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[rc] != 2 || got[project] != 1 {
		t.Errorf("InUse = %v, want %s: 2 and %s: 1", got, rc, project)
	}
}
