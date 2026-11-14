// Package doctor reports on the health of a keyward setup.
//
// It answers three questions. Does anything reference a secret that is not there —
// which breaks a command the moment it runs. Is a credential still in plaintext
// where an agent can read it. And is anything stored that nothing references any
// more.
//
// The last question cannot be answered by looking at files alone. A secret might
// be referenced somewhere doctor never read, or added by hand and referenced by
// nothing on purpose. So doctor only calls something orphaned when provenance names
// a file it actually scanned and that file no longer mentions it. Everything else
// unreferenced is reported as unknown, and nothing here deletes anything.
package doctor

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/veilux-lab/keyward/internal/backup"
	"github.com/veilux-lab/keyward/internal/handle"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
	"github.com/veilux-lab/keyward/internal/migrate"
	"github.com/veilux-lab/keyward/internal/vault"
)

// Reference is one occurrence of a cap:// reference in a file.
type Reference struct {
	Name string
	File string
	Line int
}

// Plaintext is an assignment in a scanned file whose value looks like a
// credential, located by file, line and variable.
type Plaintext struct {
	File string
	Line int
	Name string
	migrate.Detection
}

// Unmovable is text in a scanned file that looks like a credential and that
// migrate cannot move, such as a comment, located by file, line and kind.
type Unmovable struct {
	File string
	migrate.UnmovableLine
}

// Finding is a stored secret that nothing scanned refers to, with an explanation
// the reader can act on.
type Finding struct {
	vault.Entry

	// Detail says why this entry is in the list it is in. It is the difference
	// between a report someone can act on and a list of names.
	Detail string
}

// Report is the outcome of a check. It holds names and paths only, never values.
type Report struct {
	// Scanned and Absent together state the report's coverage. Without them,
	// "unreferenced" reads as "unused" — the inference that gets a credential
	// deleted.
	Scanned []string
	Absent  []string

	// Malformed and Dangling are problems: each breaks a command today.
	Malformed []Reference
	Dangling  []Reference

	// Plaintext, Unmovable and Literals look like credentials: values in the
	// files, other text in them, and values in MCP server definitions. Those of a
	// known shape, and the nearby lines listed with them, are problems; the rest
	// only may be credentials.
	Plaintext []Plaintext
	Unmovable []Unmovable
	Literals  []mcpconfig.Literal

	// Orphaned is verifiably unused: provenance names a scanned file that no longer
	// references it.
	Orphaned []Finding

	// Unknown is unreferenced but not provably unused. Leave alone unless sure.
	Unknown []Finding

	// Referenced names secrets that are stored and used.
	Referenced []string
}

// Problems names each kind of problem found, with its count. A dangling or
// malformed reference breaks a command; a credential in plaintext is open to any
// agent, and is counted as the report's list of them counts it, every line of a
// range in it as one. Orphans, unknowns and the other values that only may be
// credentials do not count: they cost a line of output, not a failure.
func (r *Report) Problems() []string {
	problems := r.brokenReferences()
	if certain, _ := r.plaintextEntries(); certain.lines > 0 {
		problems = append(problems, fmt.Sprintf("%d credential(s) in plaintext", certain.lines))
	}
	return problems
}

// brokenReferences names each kind of reference that fails when used, with its
// count.
func (r *Report) brokenReferences() []string {
	var broken []string
	if n := len(r.Dangling); n > 0 {
		broken = append(broken, fmt.Sprintf("%d reference(s) to secrets that are not in the vault", n))
	}
	if n := len(r.Malformed); n > 0 {
		broken = append(broken, fmt.Sprintf("%d malformed reference(s)", n))
	}
	return broken
}

// Checks says how each of the report's checks came out, in the order the
// checklist shows them.
func (r *Report) Checks() []Check {
	certain, possible := r.plaintextEntries()
	stored := fmt.Sprintf("%d secret(s) stored and referenced", len(r.Referenced))
	references := Check{Pass, "References", stored}
	if broken := r.brokenReferences(); len(broken) > 0 {
		references = Check{Fail, "References", stored + "; " + strings.Join(broken, "; ") + ", listed above"}
	}
	known := Check{Pass, "Known secrets", "none in plaintext"}
	if certain.lines > 0 {
		known = Check{Fail, "Known secrets", fmt.Sprintf("%d credential(s) in plaintext, listed above", certain.lines)}
	}
	maybe := Check{Pass, "Maybe secrets", "nothing else looks like one"}
	if possible.lines > 0 {
		maybe = Check{Attention, "Maybe secrets", fmt.Sprintf("%d value(s) that may be credentials, listed above", possible.lines)}
	}
	var unused []string
	if n := len(r.Orphaned); n > 0 {
		unused = append(unused, fmt.Sprintf("%d secret(s) whose source no longer references them", n))
	}
	if n := len(r.Unknown); n > 0 {
		unused = append(unused, fmt.Sprintf("%d secret(s) nothing scanned refers to", n))
	}
	unreferenced := Check{Pass, "Unused", "none"}
	if len(unused) > 0 {
		unreferenced = Check{Attention, "Unused", strings.Join(unused, "; ") + ", listed above"}
	}
	return []Check{references, known, maybe, unreferenced}
}

// Run scans paths and the configs servers were read from, compares what they
// reference against what is stored, and looks for credentials still in plaintext
// in those files and in servers.
//
// A path that does not exist is recorded in Absent rather than failing: the default
// set includes files many machines will not have.
func Run(store vault.Store, paths []string, servers []mcpconfig.Server) (*Report, error) {
	r := &Report{Literals: mcpconfig.Literals(servers)}

	// refs maps a name, lowercased as keyward run reads it, to every place it is
	// referenced.
	refs := make(map[string][]Reference)
	// scanned lets provenance be judged: a file absent from this set was never
	// looked at, so it can prove nothing.
	scanned := make(map[string]bool)
	// seen keeps a file named twice, perhaps by a relative path, from being
	// counted twice.
	seen := make(map[string]bool)
	// configs names the MCP configs whose servers were read, such as a
	// project's .mcp.json, beyond those IsMCPConfig names. Each is scanned for
	// references too: keyward run resolves one in a server's env, so a secret
	// only a server's config names is still in use.
	configs := make(map[string]bool)
	files := slices.Clone(paths)
	for _, s := range servers {
		file, _, _ := strings.Cut(s.Config, " (project ")
		if !configs[file] {
			configs[file] = true
			files = append(files, file)
		}
	}

	for _, path := range files {
		key := path
		if abs, err := filepath.Abs(path); err == nil {
			key = abs
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		content, err := os.ReadFile(path)
		if err != nil {
			// Unreadable and missing are the same thing here: no evidence either way.
			r.Absent = append(r.Absent, path)
			continue
		}
		r.Scanned = append(r.Scanned, path)
		scanned[path] = true

		valid, malformed := scanReferences(path, content)
		for _, ref := range valid {
			name, _ := handle.Normalize(ref.Name)
			refs[name] = append(refs[name], ref)
		}
		r.Malformed = append(r.Malformed, malformed...)
		// MCP configs are checked through their servers: read as shell, they
		// would count a token twice.
		if !IsMCPConfig(path) && !configs[key] {
			plaintext, unmovable := scanPlaintext(path, content)
			r.Plaintext = append(r.Plaintext, plaintext...)
			r.Unmovable = append(r.Unmovable, unmovable...)
		}
	}

	entries, err := store.Entries()
	if err != nil {
		return nil, fmt.Errorf("reading the vault: %w", err)
	}
	stored := make(map[string]bool, len(entries))
	for _, e := range entries {
		stored[e.Name] = true
	}

	// A reference with nothing behind it fails the next time the command runs.
	for name, occurrences := range refs {
		if !stored[name] {
			r.Dangling = append(r.Dangling, occurrences...)
		}
	}
	sortReferences(r.Dangling)
	sortReferences(r.Malformed)

	for _, e := range entries {
		// Backup keys are referenced by backups, not files.
		if backup.IsKey(e.Name) {
			continue
		}
		if len(refs[e.Name]) > 0 {
			// Referenced anywhere at all is enough. Provenance pointing elsewhere just
			// means the value moved.
			r.Referenced = append(r.Referenced, e.Name)
			continue
		}
		r.classifyUnreferenced(e, scanned)
	}

	sort.Strings(r.Referenced)
	sortFindings(r.Orphaned)
	sortFindings(r.Unknown)
	return r, nil
}

// classifyUnreferenced decides whether an unreferenced entry is provably unused.
//
// The distinction is the whole point of recording provenance. Only the first case
// is a fact; the rest are absence of evidence, and treating them as the same thing
// is how a credential gets deleted because nobody looked in the right file.
func (r *Report) classifyUnreferenced(e vault.Entry, scanned map[string]bool) {
	if e.Note == "" {
		r.Unknown = append(r.Unknown, Finding{
			Entry:  e,
			Detail: "no record of where it came from, so it was probably added by hand",
		})
		return
	}

	source := sourceFile(e.Note)
	switch {
	case scanned[source]:
		r.Orphaned = append(r.Orphaned, Finding{
			Entry:  e,
			Detail: fmt.Sprintf("came from %s, which no longer references it", e.Note),
		})
	case !fileExists(source):
		r.Unknown = append(r.Unknown, Finding{
			Entry:  e,
			Detail: fmt.Sprintf("came from %s, which no longer exists", source),
		})
	default:
		r.Unknown = append(r.Unknown, Finding{
			Entry:  e,
			Detail: fmt.Sprintf("came from %s, which was not scanned", source),
		})
	}
}

// scanReferences finds every cap:// reference in content, by text rather than by
// parsing a format — which is what lets one scanner cover shell files, .env files,
// and the JSON and TOML that MCP servers use.
//
// Only the reference itself is ever extracted. The surrounding line may hold a
// credential that has not been migrated yet, and none of it is retained.
func scanReferences(path string, content []byte) (valid, malformed []Reference) {
	for i, line := range strings.Split(string(content), "\n") {
		rest := line
		for {
			at := strings.Index(rest, handle.Prefix)
			if at < 0 {
				break
			}
			rest = rest[at+len(handle.Prefix):]

			name := rest[:nameLength(rest)]
			ref := Reference{Name: name, File: path, Line: i + 1}
			if _, err := handle.Normalize(name); err != nil {
				malformed = append(malformed, ref)
			} else {
				valid = append(valid, ref)
			}
		}
	}
	return valid, malformed
}

// scanPlaintext finds assignments whose value still looks like a credential, and
// the credential-shaped text migrate cannot move. It calls Detect itself rather
// than building a migration plan, which refuses a whole file when two names
// collide. A line whose comment holds migrate.IgnoreMarker is left out, and so is
// a placeholder.
func scanPlaintext(path string, content []byte) ([]Plaintext, []Unmovable) {
	f := migrate.Scan(content)
	var found []Plaintext
	for _, a := range f.Assignments {
		if strings.Contains(a.Trailer, migrate.IgnoreMarker) || migrate.Placeholder(a.Value) {
			continue
		}
		if d := migrate.Detect(a.Name, a.Value); d.Secret || d.Possible {
			found = append(found, Plaintext{File: path, Line: a.Line, Name: a.Name, Detection: d})
		}
	}
	var unmovable []Unmovable
	for _, u := range f.Unmovable() {
		unmovable = append(unmovable, Unmovable{File: path, UnmovableLine: u})
	}
	return found, unmovable
}

// InUse counts, per file, the references to secrets that are stored. It reads
// paths plus every file a stored secret was migrated from, so a file outside the
// defaults is still found. Missing and unreadable files are skipped.
func InUse(store vault.Store, paths []string) (map[string]int, error) {
	entries, err := store.Entries()
	if err != nil {
		return nil, err
	}
	stored := map[string]bool{}
	files := append([]string(nil), paths...)
	for _, e := range entries {
		if backup.IsKey(e.Name) {
			continue
		}
		stored[e.Name] = true
		if e.Note != "" {
			files = append(files, sourceFile(e.Note))
		}
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, path := range files {
		if seen[path] {
			continue
		}
		seen[path] = true
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		refs, _ := scanReferences(path, content)
		for _, ref := range refs {
			if name, err := handle.Normalize(ref.Name); err == nil && stored[name] {
				counts[path]++
			}
		}
	}
	return counts, nil
}

// nameLength measures the leading run of characters a reference name may contain.
func nameLength(s string) int {
	i := 0
	for i < len(s) {
		c := s[i]
		ok := c == '-' || c == '_' || c == '.' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !ok {
			break
		}
		i++
	}
	return i
}

// sourceFile strips the line number from a "path:line" note. A path may itself
// contain a colon, so only a trailing all-digit segment counts.
func sourceFile(note string) string {
	i := strings.LastIndexByte(note, ':')
	if i <= 0 {
		return note
	}
	if _, err := strconv.Atoi(note[i+1:]); err != nil {
		return note
	}
	return note[:i]
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func sortReferences(refs []Reference) {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].File != refs[j].File {
			return refs[i].File < refs[j].File
		}
		return refs[i].Line < refs[j].Line
	})
}

func sortFindings(f []Finding) {
	sort.Slice(f, func(i, j int) bool { return f[i].Name < f[j].Name })
}

// The tags of a row in a list of credentials say how to fix it: migrate moves its
// value, add stores it, edit means removing it by hand, and an MCP server's fix
// follows its row.
const (
	tagMigrate = "migrate"
	tagAdd     = "add"
	tagEdit    = "edit"
	tagMCP     = "mcp"
)

// entry is a row of a list of credentials: where it is, its tag, what holds it
// and why it looks like one. An MCP server's carries its fix, which differs from
// server to server. file and line place a line's entry, lines counts the lines it
// names, and paired marks one whose line is listed twice, for its value and for
// the comment beside it.
type entry struct {
	where, tag, what, reason, fix string
	file                          string
	line, lines                   int
	paired                        bool
}

// listing is the entries of one list in the report, how many lines or MCP fields
// they name, whether one is a range of lines the user may mark, whether one is a
// line the user may mark as holding no secret, and whether one is paired.
type listing struct {
	entries                  []entry
	lines                    int
	ranges, markable, paired bool
}

// eachLine is what the advice to mark a line adds where l lists a range of lines
// the user may mark.
func (l listing) eachLine() string {
	if l.ranges {
		return "marking each line of a range, "
	}
	return ""
}

// maxGap is how many lines apart flagged lines can be and still be listed as one
// range.
const maxGap = 3

// plaintextEntries lists each value that looks like a credential: those of a
// known shape, and those that only may be credentials. Nearby text migrate cannot
// move is listed as one range, as stretches merges it, with those of a known
// shape if one of its lines is. Lines are listed in file order, and MCP servers
// after them.
func (r *Report) plaintextEntries() (certain, possible listing) {
	// add lists an entry naming lines with those of a known shape if known says one
	// of them holds one. Marking such an entry's lines would hide a credential, so
	// that is never advised.
	add := func(e entry, known, markable bool) {
		list := &possible
		if known {
			list, markable = &certain, false
		}
		list.entries = append(list.entries, e)
		list.lines += e.lines
		list.ranges = list.ranges || e.lines > 1 && markable
		list.markable = list.markable || markable
		list.paired = list.paired || e.paired
	}
	// Marking a line whose comment is listed too would hide the comment as well.
	type line struct {
		file string
		n    int
	}
	commented := map[line]bool{}
	for _, u := range r.Unmovable {
		if u.Kind == "trailer" {
			commented[line{u.File, u.Line}] = true
		}
	}
	for _, p := range r.Plaintext {
		tag := tagAdd
		if p.Secret {
			tag = tagMigrate
		}
		paired := commented[line{p.File, p.Line}]
		add(entry{where: fmt.Sprintf("%s:%d", p.File, p.Line), tag: tag, what: p.Name, reason: p.Reason, file: p.File, line: p.Line, lines: 1, paired: paired},
			p.KnownShape, !paired)
	}
	for _, s := range stretches(r.Unmovable, r.Plaintext) {
		e := entry{where: fmt.Sprintf("%s:%d", s.File, s.Line), tag: tagEdit, what: s.Kind, reason: migrate.Describe(s.Labels), file: s.File, line: s.Line, lines: s.lines, paired: s.valued}
		if s.lines > 1 {
			e.where, e.what, e.reason = fmt.Sprintf("%s:%d-%d", s.File, s.Line, s.last), fmt.Sprintf("%d %s lines", s.lines, s.Kind), migrate.Describe(migrate.Kinds(s.Labels))
		}
		add(e, s.KnownShape, !s.valued)
	}
	// Files keep the order they were read in. A stable sort keeps a value, added
	// first, before the comment beside it.
	rank := func(file string) int {
		if i := slices.Index(r.Scanned, file); i >= 0 {
			return i
		}
		return len(r.Scanned)
	}
	byPlace := func(a, b entry) int {
		return cmp.Or(cmp.Compare(rank(a.file), rank(b.file)), strings.Compare(a.file, b.file), cmp.Compare(a.line, b.line))
	}
	slices.SortStableFunc(certain.entries, byPlace)
	slices.SortStableFunc(possible.entries, byPlace)
	// keyward run resolves only its environment, so a field outside env reads a
	// reference through a variable. One in env does too, of its own name: unwrap
	// and uninstall read it from that, which restoring ~/.zshrc then sets. wrap
	// changes a project's server in its folder, which must still exist.
	for _, l := range r.Literals {
		field, _, _ := strings.Cut(l.Field, " (")
		copilot := "Copilot CLI"
		if l.Client != mcpconfig.Copilot {
			copilot += ", which starts a project's .mcp.json servers too,"
		}
		fix := "store it with keyward add NAME, write ${VAR} in its place, add export VAR='cap://NAME' to ~/.zshrc, and run keyward mcp wrap"
		key, inEnv := strings.CutPrefix(field, "env.")
		switch name, inHTTPHeaders := strings.CutPrefix(field, "http_headers."); {
		case inEnv && l.Client == "Codex":
			// Codex fills no variable in env, but passes on those env_vars names.
			fix = "store it with keyward add NAME, remove it and add " + strconv.Quote(key) + " to env_vars, add export " + key + "='cap://NAME' to ~/.zshrc, and run keyward mcp wrap"
		case inEnv:
			placeholder := "${" + key + "}"
			if l.Client == "Cursor" {
				placeholder = "${env:" + key + "}"
			}
			fix = "store it with keyward add NAME, write " + placeholder + " in its place, add export " + key + "='cap://NAME' to ~/.zshrc, and run keyward mcp wrap"
		case inHTTPHeaders:
			// Codex fills a variable only in the headers env_http_headers names.
			fix = "store it with keyward add NAME, move it to env_http_headers = { " + strconv.Quote(name) + " = \"VAR\" }, "
			if strings.EqualFold(name, "Authorization") {
				fix += "or for a Bearer token, store the token alone and use bearer_token_env_var = \"VAR\"; "
			}
			fix += "add export VAR='cap://NAME' to ~/.zshrc, and run keyward mcp wrap"
		case field == "url" || strings.HasSuffix(l.Field, "(its mcp-remote URL)"):
			// mcp-remote puts the URL in its command line, so wrap puts a migrated
			// secret there only if given --allow-command-line.
			header := "as ${VAR}"
			if l.Client == "Codex" {
				header = "with env_http_headers = { \"HEADER\" = \"VAR\" }"
			}
			fix = "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and send it in a header " + header + ", if the server takes it there, " +
				"or else write ${VAR} in its place, which wrap puts in mcp-remote's command line and log only if given --allow-command-line; then run keyward mcp wrap"
			if l.Copilot {
				fix = "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and send it in a header as ${VAR}, if the server takes it there, " +
					"as keyward starts a remote server through mcp-remote, which takes the URL as an argument, where " + copilot + " fills in a ${VAR} itself; then run keyward mcp wrap"
			}
		case strings.HasPrefix(l.Field, "args[") && !strings.Contains(l.Field, " ("):
			// keyward run refuses a secret as an argument unless given
			// --allow-command-line, but wrap leaves one in a header to mcp-remote.
			env := "in env as VAR"
			if l.Client == "Codex" {
				env = "with env_vars = [\"VAR\"]"
			}
			fix = "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and pass it " + env + ", if the server reads it from there, " +
				"or else write ${VAR} in its place, which wrap puts in the server's command line only if given --allow-command-line, unless it is in an mcp-remote --header; " +
				"then run keyward mcp wrap"
			if l.Copilot {
				fix = "store it with keyward add NAME, add export VAR='cap://NAME' to ~/.zshrc, and pass it in env as VAR, if the server reads it from there, " +
					"as " + copilot + " fills in a ${VAR} in its command itself; then run keyward mcp wrap"
			}
		}
		config, _, _ := strings.Cut(l.Config, " (project ")
		switch {
		case mcpconfig.Gone(l.Project):
			fix = "remove the server from " + config + " by hand, with Claude Code closed, as its project's folder no longer exists"
		case l.Project != "":
			fix += " in " + l.Project
		}
		// What only may be a credential is fixed if it is one.
		if !l.KnownShape {
			fix = "if it is one, " + fix
		}
		// The project Config names after the path follows what holds the value.
		what := fmt.Sprintf("%s server %s, %s%s", l.Client, l.Server, l.Field, l.Config[len(config):])
		add(entry{where: config, tag: tagMCP, what: what, reason: l.Reason, fix: fix, lines: 1}, l.KnownShape, false)
	}
	return certain, possible
}

// A stretch is lines of one file holding text migrate cannot move the same way,
// each within maxGap lines of the last and none listed apart between them: the
// first line, with every line's labels and a known shape if any line has one,
// where it ends, and how many lines it holds. valued marks a trailer whose line's
// value is listed too, which stays alone.
type stretch struct {
	Unmovable
	last, lines int
	valued      bool
}

// stretches merges the lines of found into stretches, in file order. A line joins
// only the stretch of the line listed just before it, never across a value of
// plain, so marking each line of a range marks no line of another entry.
func stretches(found []Unmovable, plain []Plaintext) []stretch {
	values := map[string][]int{}
	for _, p := range plain {
		values[p.File] = append(values[p.File], p.Line)
	}
	var merged []stretch
	for _, u := range found {
		lines := values[u.File]
		i := sort.SearchInts(lines, u.Line)
		valued := i < len(lines) && lines[i] == u.Line
		if n := len(merged); n > 0 && !valued {
			s := &merged[n-1]
			if s.File == u.File && s.Kind == u.Kind && !s.valued && u.Line-s.last <= maxGap &&
				(i == 0 || lines[i-1] <= s.last) {
				s.last, s.lines, s.KnownShape = u.Line, s.lines+1, s.KnownShape || u.KnownShape
				s.Labels = append(s.Labels, u.Labels...)
				continue
			}
		}
		u.Labels = slices.Clone(u.Labels)
		merged = append(merged, stretch{Unmovable: u, last: u.Line, lines: 1, valued: valued})
	}
	return merged
}

// DefaultPaths returns the files doctor reads when none are given: the shell
// startup files, a .env in the working directory, and the config of the agents
// most likely to hold references.
//
// The list is intentionally broad. Every file added makes an "unreferenced" verdict
// more trustworthy, and a file that does not exist costs one line of output.
func DefaultPaths(home, workdir string) []string {
	rel := []string{
		".zshrc", ".zshenv", ".zprofile", ".zlogin",
		".bashrc", ".bash_profile", ".profile",
		".claude.json",
		filepath.Join(".codex", "config.toml"),
	}
	paths := make([]string, 0, len(rel)+1)
	for _, r := range rel {
		paths = append(paths, filepath.Join(home, r))
	}
	if workdir != "" {
		paths = append(paths, filepath.Join(workdir, ".env"))
	}
	return paths
}

// IsMCPConfig reports whether path is the Claude Code or Codex config among the
// default paths. keyward reads the MCP servers in those, not their lines.
func IsMCPConfig(path string) bool {
	return filepath.Base(path) == ".claude.json" ||
		filepath.Base(path) == "config.toml" && filepath.Base(filepath.Dir(path)) == ".codex"
}
