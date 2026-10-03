package doctor_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/doctor"
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

	r, err := doctor.Run(store(t, map[string]string{"alpha": "", "beta": ""}), []string{rc})
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

	r, err := doctor.Run(store(t, map[string]string{"splunk-mcp-token": "", "toml-token": ""}), []string{js, toml})
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

	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(r.String(), secret) {
		t.Errorf("the report echoed a plaintext secret:\n%s", r.String())
	}
}

// ===========================================================================
// Dangling references — the class that breaks a command today
// ===========================================================================

func TestDanglingReferences(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://present'\nexport B='cap://absent'\n")

	r, err := doctor.Run(store(t, map[string]string{"present": ""}), []string{rc})
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
	if !r.HasProblems() {
		t.Error("HasProblems() = false with a dangling reference")
	}
	if !strings.Contains(r.String(), "keyward add absent") {
		t.Errorf("the report does not say how to fix it:\n%s", r.String())
	}
}

// A reference that cannot be parsed will fail at run time, so it is a problem too.
func TestMalformedReferences(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://-leading-hyphen'\n")

	r, err := doctor.Run(vault.NewMemory(), []string{rc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Malformed) != 1 {
		t.Fatalf("Malformed = %v, want one", r.Malformed)
	}
	if !r.HasProblems() {
		t.Error("HasProblems() = false with a malformed reference")
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

	r, err := doctor.Run(s, []string{rc})
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
	if r.HasProblems() {
		t.Error("HasProblems() = true for an orphan alone")
	}
	if !strings.Contains(r.String(), "keyward rm removed") {
		t.Errorf("the report does not offer the removal command:\n%s", r.String())
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
	r, err := doctor.Run(s, []string{scanned})
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

	r, err := doctor.Run(s, []string{rc, env})
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

// ===========================================================================
// Coverage honesty
// ===========================================================================

// The report has to say what it looked at. Without that, "unreferenced" reads as
// "unused", which is the inference that gets a credential deleted.
func TestReportStatesItsCoverage(t *testing.T) {
	dir := t.TempDir()
	rc := write(t, dir, ".zshrc", "export A='cap://alpha'\n")
	missing := filepath.Join(dir, ".bashrc")

	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc, missing})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if strings.Join(r.Scanned, ",") != rc {
		t.Errorf("Scanned = %v, want just %s", r.Scanned, rc)
	}
	if strings.Join(r.Absent, ",") != missing {
		t.Errorf("Absent = %v, want %s", r.Absent, missing)
	}
	out := r.String()
	if !strings.Contains(out, rc) {
		t.Errorf("the report does not list the file it scanned:\n%s", out)
	}
	if !strings.Contains(out, ".bashrc") {
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

	r, err := doctor.Run(s, []string{odd, plain})
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

	r, err := doctor.Run(vault.NewMemory(), []string{b, a})
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
	rc := write(t, dir, ".zshrc", "A=cap://absent\nB=cap://-malformed\nC=cap://present\n")
	missing := filepath.Join(dir, "gone.env")

	s := store(t, map[string]string{
		"present": rc + ":3",
		"orphan":  rc + ":9",
		"by-hand": "",
	})

	r, err := doctor.Run(s, []string{rc, missing})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	out := r.String()
	for _, want := range []string{
		"not read",             // Absent
		"not in the vault",     // Dangling
		"malformed",            // Malformed
		"no longer references", // Orphaned
		"may still be in use",  // Unknown
		"stored and referenced",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report omits the %q section:\n%s", want, out)
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
	if _, err := doctor.Run(brokenStore{}, nil); err == nil {
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

	r, err := doctor.Run(store(t, map[string]string{"alpha": rc + ":1"}), []string{rc})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r.HasProblems() {
		t.Error("HasProblems() = true for a healthy setup")
	}
	out := r.String()
	for _, unwanted := range []string{"orphaned", "not in the vault", "malformed"} {
		if strings.Contains(strings.ToLower(out), unwanted) {
			t.Errorf("a clean report mentions %q:\n%s", unwanted, out)
		}
	}
}

// Duplicate references to one name are normal — the same token in a shell file and
// an MCP config — and must not be double reported.
func TestDuplicateReferencesCountOnce(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, ".zshrc", "export T='cap://shared'\n")
	b := write(t, dir, "mcp.json", `{"env":{"T":"cap://shared"}}`)

	r, err := doctor.Run(store(t, map[string]string{"shared": ""}), []string{a, b})
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

	r, err := doctor.Run(vault.NewMemory(), []string{a, b})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.Dangling) != 2 {
		t.Errorf("Dangling = %+v, want one per occurrence", r.Dangling)
	}
}
