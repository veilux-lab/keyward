package mcpconfig_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// Fake credentials. A Literal says where each one is and must never hold it.
const (
	headerToken = "ghp_FakeHeaderToken0000000000000000000000"
	argToken    = "ghp_FakeArgumentToken00000000000000000000"
	openAIKey   = "sk-proj-FakeOpenAIKey000000000000000000"
	linearKey   = "lin_api_FakeLinearKey0000000000000000"
	jwtToken    = "eyJhbGciOiJIUzI1NiJ9.FakePayload.FakeSignature"
	urlPassword = "FakeUrlPassw0rd"
	queryKey    = "AIzaFakeQueryStringKey0000000000000000"
	dbPassword  = "FakeDbPassw0rd"
	// Only its name marks this one: entropy alone would not flag it.
	namedValue = "correct-horse-battery-staple-9271"
	// Only its randomness marks this one.
	randomValue = "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i"
	// Only the Bearer before it marks this one.
	opaqueToken = "FakeOpaqueBearerToken0000"
	// One in a JSON or quoted argument, which a script quotes again.
	anthropicKey = "sk-ant-api03-FakeJsonCfgKey0000000000000000"
	// One in JSON written without spaces.
	compactToken = "ghp_FakeSmitheryCompact0000000000000000"
	// Header values given to mcp-remote as arguments. Only its header's name marks
	// each but the one with a known prefix.
	opaqueHeader = "FakeOpaqueArgHeader0000"
	noSpaceKey   = "sk-ant-api03-FakeNoSpaceHeader0000000000"
	schemeToken  = "FakeOpaqueTokenScheme0000"
	hexHeader    = "abcdef0123456789abcdef0123456789abcdef01"
)

func literalsFixture(t *testing.T) (home, workdir string) {
	t.Helper()
	home, workdir = t.TempDir(), t.TempDir()
	other := filepath.Join(t.TempDir(), "other-project")
	write(t, filepath.Join(home, ".claude.json"), `{
  "mcpServers": {
    "github": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer `+headerToken+`"}},
    "api": {"type": "http", "url": "https://api.example.com/v1/mcp", "headers": {"X-Api-Key": "`+namedValue+`"}},
    "remote": {"type": "http", "url": "https://bot:`+urlPassword+`@mcp.example.com/mcp"},
    "query": {"type": "sse", "url": "https://mcp.example.com/sse?key=`+queryKey+`&region=us"},
    "pagerduty": {"command": "uvx", "args": ["pagerduty-mcp"], "env": {"PAGERDUTY_API_KEY": "`+namedValue+`", "MY_THING": "`+randomValue+`", "LEVEL": "info", "PD_KEY": "${PD_KEY}", "WRAPPED": "cap://pagerduty-key"}}
  },
  "projects": {
    "`+workdir+`": {"mcpServers": {"here": {"command": "tool", "args": ["--token", "`+argToken+`"]}}},
    "`+other+`": {"mcpServers": {"there": {"command": "uvx", "args": ["openai-mcp"], "env": {"OPENAI_API_KEY": "`+openAIKey+`"}}}}
  }
}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), `[mcp_servers.linear]
url = "https://mcp.example.com/linear"
http_headers = { "X-Workspace" = "acme", Authorization = "Bearer `+linearKey+`" }

[mcp_servers.figma]
url = "https://mcp.example.com/figma"
bearer_token_env_var = "FIGMA_TOKEN"

[mcp_servers.figma.http_headers]
X-Api-Key = "`+namedValue+`"

[mcp_servers.pd]
command = "uvx"
enabled = false

[mcp_servers.pd.env]
PD_TOKEN = "`+jwtToken+`"
`)
	write(t, filepath.Join(home, ".cursor", "mcp.json"), `{"mcpServers": {"postgres": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://app:`+dbPassword+`@db.internal:5432/app"]}}}`)
	return home, workdir
}

// Every value a definition holds is checked, in every client and every Claude Code
// project. A placeholder or a reference is not plaintext, so it is not reported.
func TestLiteralsFindCredentialsWrittenIntoServerDefinitions(t *testing.T) {
	home, workdir := literalsFixture(t)
	servers, errs := mcpconfig.LoadAll(home, workdir)
	if len(errs) != 0 {
		t.Fatalf("LoadAll errors: %v", errs)
	}
	literals := mcpconfig.Literals(servers)
	got := map[string]bool{}
	for _, l := range literals {
		got[l.Client+" "+l.Server+" "+l.Field] = l.KnownShape
	}
	// true marks a value whose own form proves it; false one only its name suggests.
	want := map[string]bool{
		"Claude Code github headers.Authorization":    true,
		"Claude Code api headers.X-Api-Key":           false,
		"Claude Code remote url":                      true,
		"Claude Code query url":                       true,
		"Claude Code pagerduty env.PAGERDUTY_API_KEY": false,
		"Claude Code pagerduty env.MY_THING":          false,
		"Claude Code here args[1]":                    true,
		"Claude Code there env.OPENAI_API_KEY":        true,
		"Codex linear http_headers.Authorization":     true,
		"Codex figma http_headers.X-Api-Key":          false,
		"Codex pd env.PD_TOKEN":                       true,
		"Cursor postgres args[2]":                     true,
	}
	if len(got) != len(want) {
		t.Errorf("literals = %v, want %v", got, want)
	}
	for field, shape := range want {
		if known, ok := got[field]; !ok || known != shape {
			t.Errorf("%s: found %v, KnownShape %v; want found, KnownShape %v", field, ok, known, shape)
		}
	}
	if !slices.IsSortedFunc(literals, func(a, b mcpconfig.Literal) int {
		return strings.Compare(a.Client+a.Config+a.Server+a.Field, b.Client+b.Config+b.Server+b.Field)
	}) {
		t.Errorf("literals are not sorted: %v", literals)
	}

	dump := fmt.Sprintf("%#v", literals)
	for _, value := range []string{headerToken, argToken, openAIKey, linearKey, jwtToken, urlPassword, queryKey, dbPassword, namedValue, randomValue} {
		if strings.Contains(dump, value) {
			t.Errorf("a Literal holds the value %q", value)
		}
	}
}

// In an argument, a credential prefix counts only where a value starts: sk- also
// ends the word task-, and keyward's own bridge writes Bearer before a placeholder.
// A word shaped like a key may still be one, whatever is inside it.
func TestLiteralsInArgumentsOnlyWhereAValueStarts(t *testing.T) {
	args := []string{
		"--token", argToken, // [1]: the start of an argument
		"--api-key=" + openAIKey,                          // [2]: after =
		"Authorization: Bearer FakeOpaqueBearerToken0000", // [3]: after ": ", where Bearer starts the value
		"Authorization:Bearer " + headerToken,             // [4]: after Bearer
		"build-sk-AbCdEfGhIjKlMnOpQrStUvWxYz0123",         // [5]: inside a word, which is shaped like a key
		"Authorization: Bearer ${GITHUB_TOKEN}",           // a placeholder
		`exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer "'$''{GITHUB_TOKEN}'" --transport http-only`,
		`{"token": "` + jwtToken + `"}`,                   // [8]: after ": " and an opening quote
		"--lang=sk-SK --key=" + argToken,                  // [9]: a word shaped like a short key comes first
		"https://mcp.example.com/" + headerToken + "/mcp", // [10]: where a segment of a URL's path starts
		// [11] and [12]: behind a quote a script escapes, as wrap writes JSON or a quoted value
		`exec npx -y @smithery/cli run @org/server --config "{\"apiKey\": \"` + anthropicKey + `\"}"`,
		`exec sh -c "API_KEY=\"` + anthropicKey + `\" exec some-mcp"`,
	}
	config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"probe": map[string]any{"command": "x", "args": args}}})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), string(config))
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var fields []string
	for _, l := range mcpconfig.Literals(servers) {
		if l.KnownShape != (l.Field != "args[5]") {
			t.Errorf("%s: KnownShape = %v (%s)", l.Field, l.KnownShape, l.Reason)
		}
		fields = append(fields, l.Field)
	}
	if got, want := strings.Join(fields, ","), "args[10],args[11],args[12],args[1],args[2],args[3],args[4],args[5],args[8],args[9]"; got != want {
		t.Errorf("fields = %s, want %s", got, want)
	}
}

// An option's name marks the value after it as a header's name does its value, as
// in --api-key VALUE or --app-key=VALUE, and a token shaped like a key, of hex
// digits or mixing cases and digits, may be one where a value or a segment of a
// URL's path starts. With nothing but a name or a shape to go on, each only may be
// a credential. Randomness alone does not count after an option, as a package's
// name after -y has as much.
func TestLiteralsFindAValueByItsOptionsNameOrItsShape(t *testing.T) {
	const (
		hexKey = "0123456789abcdef0123456789abcdef"
		appKey = "Zx8Kq2Lm9Pw4Rt7Yv1Nb5Hc3Jd6Fg0Sa"
		uuid   = "3f2a9c1e-7b4d-4e8f-9a6b-2c1d0e5f7a8b"
		named  = "FakeOpaqueOptionValue"
	)
	args := []string{
		"-y", "@modelcontextprotocol/server-github",
		"--api-key", hexKey, // [3]: its name and its shape
		"--app-key=" + appKey, // [4]: after an option and =
		"--key", uuid,         // [6]: its shape alone
		"--token", named, // [8]: its option's name alone
		"--dd-api-key=" + hexKey, // [9]
		"--root", "${HOME}", "--name", "my-server", "--key-file", "/etc/keys/key.pem", "--region", "us-east-1",
		"exec dd-mcp --api-key " + hexKey + ` --root "$HOME"`, // [18]: a word of a script keyward writes
	}
	config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
		"dd":   map[string]any{"command": "npx", "args": args},
		"path": map[string]any{"type": "http", "url": "https://mcp.example.com/" + uuid + "/sse"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), string(config))
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var fields []string
	for _, l := range mcpconfig.Literals(servers) {
		if l.KnownShape || !l.Secret && !l.Possible {
			t.Errorf("%s %s: %+v, want one that only may be a credential", l.Server, l.Field, l.Detection)
		}
		fields = append(fields, l.Server+" "+l.Field)
	}
	if got, want := strings.Join(fields, ","), "dd args[18],dd args[3],dd args[4],dd args[6],dd args[8],dd args[9],path url"; got != want {
		t.Errorf("fields = %s, want %s", got, want)
	}
}

// JSON and a dict hold a value at a quote after a key's colon, spaced or not, and a
// list each element at a quote after [ or ,. A credential there is found as it is
// in {"apiKey": "..."}, behind a quote a script escapes too. Before a word that is
// not quoted, a colon, [ or , starts no value, so host:port, a URL's scheme, a
// time and a:b are passed over, even beside a word shaped like a credential.
func TestLiteralsInJSONOrAListWithOrWithoutSpaces(t *testing.T) {
	args := []string{
		`{"apiKey": "` + anthropicKey + `"}`, // [0]: the spaced form
		`{"githubPersonalAccessToken":"` + compactToken + `"}`,
		`{"apiKey":"` + anthropicKey + `"}`,
		`{'apiKey':'` + anthropicKey + `'}`,
		`{ "apiKey" :"` + anthropicKey + `" }`,
		`["` + anthropicKey + `"]`,
		`['--verbose', '` + anthropicKey + `']`,
		`exec npx -y @smithery/cli run @org/server --config "{\"apiKey\":\"` + anthropicKey + `\"}"`, // [7]
		"mcp.example.com:8443",
		"https://mcp.example.com/mcp",
		"--window=09:30-17:45",
		"--locales=slovak:sk-SK,czech:cs-CZ",
		"--mirrors=eu.example.com:443,sk-mirror.example.com:443",
		`{"url":"https://mcp.example.com/mcp","proxy":"proxy.example.com:8080","at":"09:30"}`,
	}
	config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"probe": map[string]any{"command": "x", "args": args}}})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), string(config))
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	literals := mcpconfig.Literals(servers)
	var fields []string
	for _, l := range literals {
		fields = append(fields, l.Field)
		if spaced := literals[0].Detection; l.Field != "args[1]" && l.Detection != spaced {
			t.Errorf("%s: %+v, want %+v as in the spaced form", l.Field, l.Detection, spaced)
		}
		if !l.KnownShape {
			t.Errorf("%s: KnownShape = false (%s)", l.Field, l.Reason)
		}
	}
	if got, want := strings.Join(fields, ","), "args[0],args[1],args[2],args[3],args[4],args[5],args[6],args[7]"; got != want {
		t.Errorf("fields = %s, want %s", got, want)
	}
}

// A token in a URL's query or path is reported in a server's url and arguments,
// so it is in a URL that env or a header holds too, though Detect takes a URL
// without user info to hold no credential.
func TestLiteralsFindATokenInAURLThatEnvOrAHeaderHolds(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "tool": {"command": "tool", "env": {"MCP_URL": "https://mcp.example.com/`+headerToken+`/mcp", "QUERY_URL": "https://mcp.example.com/mcp?key=`+argToken+`", "BASE_URL": "https://mcp.example.com/v1/mcp"}},
    "remote": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"X-Callback": "https://hooks.example.com/`+openAIKey+`/cb"}}
  }}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), "[mcp_servers.codex]\nurl = \"https://mcp.example.com/mcp\"\nhttp_headers = { X-Callback = \"https://hooks.example.com/hook?token="+jwtToken+"\" }\n")
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var found []string
	for _, l := range mcpconfig.Literals(servers) {
		found = append(found, fmt.Sprintf("%s %s %v", l.Server, l.Field, l.KnownShape))
	}
	if got, want := strings.Join(found, ", "), "remote headers.X-Callback true, tool env.MCP_URL true, tool env.QUERY_URL true, codex http_headers.X-Callback true"; got != want {
		t.Errorf("literals = %s\nwant %s", got, want)
	}
}

// An argument can be long, as a base64 config is, and doctor, keyward mcp, wrap
// and unwrap each read every argument more than once, so reading one takes time
// that grows only with its length. So does reading a script to rewrite it.
func TestALongArgumentIsReadInTimeLinearInItsLength(t *testing.T) {
	read := func(size int) time.Duration {
		// size bytes each, with a / every few bytes, as in base64 and a URL's path.
		args := []string{"--config", strings.Repeat("QUJD/", size/5), "--url", "https://mcp.example.com/" + strings.Repeat("seg/", size/4)}
		script := `exec tool --config "` + strings.Repeat("QUJD/", size/5) + `${PD_KEY}"`
		config, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
			"cfg":    map[string]any{"command": "tool", "args": args, "env": map[string]string{"PD_KEY": "${PD_KEY}"}},
			"script": map[string]any{"command": "sh", "args": []string{"-c", script}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		write(t, filepath.Join(home, ".claude.json"), string(config))
		servers, errs := mcpconfig.Load(home, t.TempDir())
		if len(errs) != 0 {
			t.Fatal(errs)
		}
		start := time.Now()
		mcpconfig.Literals(servers)
		if findings := mcpconfig.Check(servers, map[string]string{"PD_KEY": "pagerduty-key"}); len(findings) != 2 {
			t.Fatalf("findings = %+v", findings)
		}
		return time.Since(start)
	}
	// However fast the machine, the arguments take as long to read whole as in
	// eighths; scanning back over the word at every byte took over seven times as long.
	var eighths time.Duration
	for range 8 {
		eighths += read(100_000 / 8)
	}
	if whole := read(100_000); whole > 3*eighths || whole > time.Minute {
		t.Errorf("reading three 100 KB arguments took %v whole and %v in eighths", whole, eighths)
	}
}

// wrap moves a header's text into a KW_HDR variable, away from the name and scheme
// that mark it, and puts the URL in a script. Both are still in the config, as they
// are in a bridge that is turned off or that unwrap left, so a bridge is judged as
// the remote server it stands for: what was found before wrap is found after it,
// once, named where the bridge holds it.
func TestLiteralsFindTheSameCredentialsOnceAServerIsWrapped(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {
    "opaque": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer `+opaqueToken+`", "X-Org": "${ORG_TOKEN}"}},
    "github": {"type": "http", "url": "https://api.example.com/mcp/", "headers": {"Authorization": "Bearer `+headerToken+`", "X-Org": "${ORG_TOKEN}"}},
    "api": {"type": "http", "url": "https://api.example.com/v1/mcp", "headers": {"X-Api-Key": "`+namedValue+`", "X-Org": "${ORG_TOKEN}"}},
    "remote": {"type": "http", "url": "https://bot:`+urlPassword+`@mcp.example.com/mcp", "headers": {"X-Org": "${ORG_TOKEN}"}},
    "query": {"type": "http", "url": "https://mcp.example.com/mcp?key=`+queryKey+`&region=us", "headers": {"X-Org": "${ORG_TOKEN}"}},
    "prefixed": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"X-Auth": "`+openAIKey+`:${ORG_TOKEN}"}}
  }}`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	var wrapped, off, unwrapped []mcpconfig.Server
	for _, f := range mcpconfig.Check(servers, map[string]string{"ORG_TOKEN": "org-token"}) {
		wrapped = append(wrapped, load(t, f.Name, f.Want)...)
		off = append(off, turnedOff(t, f.Name, f.Want)...)
	}
	for _, f := range mcpconfig.Undo(wrapped) {
		unwrapped = append(unwrapped, load(t, f.Name, f.Want)...)
	}
	found := func(servers []mcpconfig.Server) string {
		var out []string
		for _, l := range mcpconfig.Literals(servers) {
			out = append(out, fmt.Sprintf("%s %s %v", l.Server, l.Field, l.KnownShape))
		}
		slices.Sort(out)
		return strings.Join(out, ", ")
	}
	// true marks a value whose own form, scheme included, proves it; false one only
	// its name suggests.
	want := "api headers.X-Api-Key false, github headers.Authorization true, opaque headers.Authorization true, query url true, remote url true"
	if got := found(servers); got != want {
		t.Errorf("before wrap: %s\nwant %s", got, want)
	}
	// Detect passes over a value holding a placeholder, so text beside one is missed
	// before wrap, and found alone once wrap moves it into a variable. The script is
	// the last argument, after keyward run's own until unwrap takes them away.
	moved := func(script string) string {
		return "api env.KW_HDR_1 (from its X-Api-Key header) false, github env.KW_HDR_1 (from its Authorization header) true, " +
			"opaque env.KW_HDR_1 (from its Authorization header) true, prefixed env.KW_HDR_1 (from its X-Auth header) true, " +
			"query " + script + " (its mcp-remote URL) true, remote " + script + " (its mcp-remote URL) true"
	}
	for _, tc := range []struct {
		form, script string
		servers      []mcpconfig.Server
	}{{"wrapped", "args[6]", wrapped}, {"turned off", "args[6]", off}, {"unwrapped", "args[1]", unwrapped}} {
		if got, want := found(tc.servers), moved(tc.script); got != want || len(tc.servers) != 6 {
			t.Errorf("%d server(s) %s: %s\nwant %s", len(tc.servers), tc.form, got, want)
		}
		dump := fmt.Sprintf("%#v", mcpconfig.Literals(tc.servers))
		for _, value := range []string{opaqueToken, headerToken, namedValue, urlPassword, queryKey, openAIKey} {
			if strings.Contains(dump, value) {
				t.Errorf("%s: a Literal holds the value %q", tc.form, value)
			}
		}
	}
}

// mcp-remote takes a header as an argument, after --header or in --header=, as
// Name: value or Name:value. Each is judged by its name and scheme, as the same
// header is in a bridge, and so is each in the script that wrap writes, which
// holds them all, and that unwrap leaves.
func TestLiteralsJudgeAHeaderArgumentAsABridgesHeader(t *testing.T) {
	args := []string{"-y", "mcp-remote", "https://api.example.com/mcp", "--header", "Authorization: Bearer ${GITHUB_TOKEN}", "--header", "X-Api-Key: " + opaqueHeader,
		"--header", "X-Other-Key:" + noSpaceKey, "--header=X-Auth: Token " + schemeToken, "--header=DD-API-KEY:" + hexHeader, "--header", "X-Upstream:Bearer " + opaqueToken}
	servers := load(t, "tool", mcpconfig.Definition{Command: "npx", Args: args, Env: map[string]string{"GITHUB_TOKEN": "${GITHUB_TOKEN}"}})
	// A bridge from an earlier keyward holds the same headers, each spaced.
	bridged := mcpconfig.Literals(load(t, "tool", bridge(`exec npx -y mcp-remote https://api.example.com/mcp --header "Authorization: Bearer $GITHUB_TOKEN"`+
		` --header "X-Api-Key: `+opaqueHeader+`" --header "X-Other-Key: `+noSpaceKey+`" --header "X-Auth: Token `+schemeToken+`" --header "DD-API-KEY: `+hexHeader+
		`" --header "X-Upstream: Bearer `+opaqueToken+`"`)))
	judged := map[string]mcpconfig.Literal{}
	for _, l := range bridged {
		judged[l.Field] = l
	}
	literals := mcpconfig.Literals(servers)
	if len(literals) != 5 || len(bridged) != 5 {
		t.Errorf("literals = %+v\nin a bridge = %+v", literals, bridged)
	}
	// Only a known prefix, Bearer among them, gives a credential's shape.
	known := map[string]bool{"X-Other-Key": true, "X-Upstream": true}
	for _, l := range literals {
		header := map[string]string{"args[6]": "X-Api-Key", "args[8]": "X-Other-Key", "args[9]": "X-Auth", "args[10]": "DD-API-KEY", "args[12]": "X-Upstream"}[l.Field]
		if want, ok := judged["args[6] (its "+header+" header)"]; !ok || l.Detection != want.Detection || !l.Secret || l.KnownShape != known[header] {
			t.Errorf("%s: %+v, want %+v as in a bridge", l.Field, l.Detection, want.Detection)
		}
	}

	findings := mcpconfig.Check(servers, refs)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	wrapped := load(t, "tool", findings[0].Want)
	undo := mcpconfig.Undo(wrapped)
	if len(undo) != 1 {
		t.Fatalf("findings once wrapped = %+v", undo)
	}
	for _, tc := range []struct {
		form, field string
		servers     []mcpconfig.Server
	}{{"wrapped", "args[6]", wrapped}, {"unwrapped", "args[1]", load(t, "tool", undo[0].Want)}} {
		found := mcpconfig.Literals(tc.servers)
		if len(found) != 1 || found[0].Field != tc.field || !found[0].KnownShape {
			t.Errorf("%s: literals = %+v, want %s, of a known shape", tc.form, found, tc.field)
		}
		literals = append(literals, found...)
	}
	dump := fmt.Sprintf("%#v", literals)
	for _, value := range []string{opaqueHeader, noSpaceKey, schemeToken, hexHeader, opaqueToken} {
		if strings.Contains(dump, value) {
			t.Errorf("a Literal holds the value %q", value)
		}
	}
}

// A bridge from an earlier keyward holds its header's text in its script.
func TestLiteralsNameTheScriptThatHoldsAnEarlierBridgesHeader(t *testing.T) {
	servers := load(t, "team", bridge(`exec npx -y mcp-remote https://api.example.com/mcp/ --header "X-Api-Key: `+headerToken+`" --header "Authorization: Bearer $GITHUB_TOKEN"`))
	if literals := mcpconfig.Literals(servers); len(literals) != 1 || literals[0].Field != "args[6] (its X-Api-Key header)" || !literals[0].KnownShape {
		t.Errorf("literals = %+v", literals)
	}
}

// turnedOff writes def as a Codex server that is turned off, and reads it.
func turnedOff(t *testing.T, name string, def mcpconfig.Definition) []mcpconfig.Server {
	t.Helper()
	var args, env []string
	for _, a := range def.Args {
		args = append(args, strconv.Quote(a))
	}
	for k, v := range def.Env {
		env = append(env, k+" = "+strconv.Quote(v))
	}
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), fmt.Sprintf("[mcp_servers.%s]\ncommand = %q\nargs = [%s]\nenv = { %s }\nenabled = false\n",
		name, def.Command, strings.Join(args, ", "), strings.Join(env, ", ")))
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 || len(servers) != 1 {
		t.Fatalf("servers = %+v, errors = %v", servers, errs)
	}
	return servers
}

// Load stays in the current folder, because wrap acts there. A token in any other
// project's servers is still plaintext on this Mac, so LoadAll reads them all,
// each with its project's folder, where wrap changes it.
func TestLoadAllReadsEveryClaudeCodeProject(t *testing.T) {
	home, workdir := literalsFixture(t)
	names := func(servers []mcpconfig.Server) []string {
		var out []string
		for _, s := range servers {
			if s.Scope == "local" {
				out = append(out, s.Name)
			}
		}
		slices.Sort(out)
		return out
	}
	current, _ := mcpconfig.Load(home, workdir)
	if got := strings.Join(names(current), ","); got != "here" {
		t.Errorf("Load's local servers = %s, want only this folder's", got)
	}
	all, _ := mcpconfig.LoadAll(home, workdir)
	if got := strings.Join(names(all), ","); got != "here,there" {
		t.Errorf("LoadAll's local servers = %s, want every project's", got)
	}
	for _, s := range all {
		if s.Name == "there" && (!strings.Contains(s.Config, "other-project") || filepath.Base(s.Project) != "other-project") {
			t.Errorf("Config = %q, Project = %q, want each to name the project", s.Config, s.Project)
		}
		if s.Name == "here" && s.Project != workdir || s.Scope == "user" && s.Project != "" {
			t.Errorf("%s: Project = %q", s.Name, s.Project)
		}
	}
	for _, l := range mcpconfig.Literals(all) {
		if l.Server == "there" && filepath.Base(l.Project) != "other-project" {
			t.Errorf("Literal %+v does not name its project", l)
		}
	}
}

// A project's own servers are in its folder's .mcp.json, which wrap changes only
// there. Load reads the current folder's; LoadAll also reads that of every
// project Claude Code lists and of each folder it is given, once, each server
// with its folder.
func TestLoadAllReadsTheMCPJSONOfEveryProjectFolder(t *testing.T) {
	home, workdir, root := t.TempDir(), t.TempDir(), t.TempDir()
	other, unlisted, gone := filepath.Join(root, "other"), filepath.Join(root, "unlisted"), filepath.Join(root, "gone")
	write(t, filepath.Join(home, ".claude.json"), `{"projects": {"`+workdir+`": {}, "`+other+`": {}, "`+gone+`": {}}}`)
	for dir, name := range map[string]string{workdir: "mine", other: "theirs", unlisted: "extra"} {
		write(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers": {"`+name+`": {"command": "srv"}}}`)
	}
	projectServers := func(servers []mcpconfig.Server) string {
		var out []string
		for _, s := range servers {
			if s.Scope == "project" {
				if s.Config != filepath.Join(s.Project, ".mcp.json") {
					t.Errorf("%s: Config = %q, Project = %q", s.Name, s.Config, s.Project)
				}
				out = append(out, s.Name+" "+filepath.Base(s.Project))
			}
		}
		slices.Sort(out)
		return strings.Join(out, ", ")
	}
	current, errs := mcpconfig.Load(home, workdir)
	all, more := mcpconfig.LoadAll(home, workdir, unlisted, other, workdir)
	if len(errs)+len(more) != 0 {
		t.Fatal(errs, more)
	}
	if got, want := projectServers(current), "mine "+filepath.Base(workdir); got != want {
		t.Errorf("Load's project servers = %s, want %s", got, want)
	}
	if got, want := projectServers(all), "extra unlisted, mine "+filepath.Base(workdir)+", theirs other"; got != want {
		t.Errorf("LoadAll's project servers = %s, want %s", got, want)
	}
}

// Cursor keeps a project's own servers in its folder's .cursor/mcp.json. Load
// reads the current folder's, and LoadAll also reads that of every project
// Claude Code lists and of each folder it is given, once each. A folder keyward
// knows of no other way, it cannot read.
func TestLoadAllReadsTheCursorConfigOfEveryProjectFolder(t *testing.T) {
	home, workdir, root := t.TempDir(), t.TempDir(), t.TempDir()
	other, unlisted := filepath.Join(root, "other"), filepath.Join(root, "unlisted")
	write(t, filepath.Join(home, ".claude.json"), `{"projects": {"`+other+`": {}}}`)
	for dir, name := range map[string]string{home: "global", workdir: "mine", other: "theirs", unlisted: "extra", filepath.Join(root, "unknown"): "unseen"} {
		write(t, filepath.Join(dir, ".cursor", "mcp.json"), `{"mcpServers": {"`+name+`": {"command": "srv"}}}`)
	}
	cursor := func(servers []mcpconfig.Server) string {
		var out []string
		for _, s := range servers {
			if s.Client == "Cursor" {
				out = append(out, s.Name)
			}
		}
		slices.Sort(out)
		return strings.Join(out, ", ")
	}
	current, errs := mcpconfig.Load(home, workdir)
	all, more := mcpconfig.LoadAll(home, workdir, unlisted, home, workdir)
	if len(errs)+len(more) != 0 {
		t.Fatal(errs, more)
	}
	if got := cursor(current); got != "global, mine" {
		t.Errorf("Load's Cursor servers = %s", got)
	}
	if got := cursor(all); got != "extra, global, mine, theirs" {
		t.Errorf("LoadAll's Cursor servers = %s", got)
	}
}

// Codex's static http_headers are read so Literals can see them. A suggestion
// moves their text into env, as it does any header's, so the bridge still sends
// them and none reaches a command line, where any process could read it. The
// note says to delete each header table the suggestion replaces.
func TestCodexHTTPHeadersMoveToEnvInSuggestions(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), `[mcp_servers.linear]
url = "https://mcp.example.com/linear"

[mcp_servers.linear.env_http_headers]
X-Linear-Token = "LINEAR_TOKEN"

[mcp_servers.linear.http_headers]
Authorization = "Bearer `+linearKey+`"
`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if literals := mcpconfig.Literals(servers); len(literals) != 1 || literals[0].Field != "http_headers.Authorization" {
		t.Errorf("literals = %+v", literals)
	}
	findings := mcpconfig.Check(servers, map[string]string{"LINEAR_TOKEN": "linear-token"})
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	f := findings[0]
	if strings.Contains(f.Suggestion+f.Note, linearKey) || slices.ContainsFunc(f.Want.Args, func(a string) bool { return strings.Contains(a, linearKey) }) {
		t.Errorf("a command line or the output carries the literal header:\n%s\n%s", f.Suggestion, f.Note)
	}
	if got, want := mcpRemoteArgs(t, f.Want), "[-y][mcp-remote][https://mcp.example.com/linear][--header][Authorization: Bearer ${KW_HDR_1}][--header][X-Linear-Token: ${LINEAR_TOKEN}][--transport][http-only]"; got != want || f.Want.Env["KW_HDR_1"] != linearKey {
		t.Errorf("mcp-remote args = %s, want %s, with KW_HDR_1 set", got, want)
	}
	for _, want := range []string{
		" and delete its [mcp_servers.linear.env_http_headers] table and its [mcp_servers.linear.http_headers] table. Other subtables",
		"KW_HDR_1 holds text from its Authorization header",
	} {
		if !strings.Contains(f.Note, want) {
			t.Errorf("note lacks %q: %s", want, f.Note)
		}
	}
}

// Codex fills no variable in http_headers, so it would send a ${VAR} there as
// written. One that reads a reference is reported, and the bridge that fixes the
// server has mcp-remote fill it in.
func TestAReferenceInCodexHTTPHeadersIsReported(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".codex", "config.toml"), `[mcp_servers.team]
url = "https://mcp.example.com/mcp"
http_headers = { "X-Team" = "${JIRA}", "X-Region" = "${REGION}" }
`)
	servers, errs := mcpconfig.Load(home, t.TempDir())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	findings := mcpconfig.Check(servers, refs)
	if len(findings) != 1 || strings.Join(findings[0].Vars, ",") != "JIRA" {
		t.Fatalf("findings = %+v", findings)
	}
	if got, want := mcpRemoteArgs(t, findings[0].Want), "[-y][mcp-remote][https://mcp.example.com/mcp][--header][X-Region: ${REGION}][--header][X-Team: ${JIRA}][--transport][http-only]"; got != want {
		t.Errorf("mcp-remote args = %s, want %s", got, want)
	}
}
