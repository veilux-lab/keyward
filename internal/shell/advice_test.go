package shell_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/shell"
)

// advised returns the advice Check's findings print, in order.
func advised(t *testing.T, sh, script string, resolved []string) []string {
	t.Helper()
	found, err := shell.Check(sh, script, resolved)
	if err != nil {
		t.Fatalf("%s: %v", script, err)
	}
	var lines []string
	for _, f := range found {
		if line := shell.Advice(f, found); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// refusals are scripts that keyward run refuses, with the advice it prints.
var refusals = []struct {
	script   string
	resolved []string
	want     string
}{
	{`curl -s -u "$JIRA_API_EMAIL:$JIRA_API_TOKEN" "$1/rest/api/3/myself"`, jira,
		`Send it on stdin instead: printf 'user = "%s:%s"\n' "$JIRA_API_EMAIL" "$JIRA_API_TOKEN" | curl -K - ...`},
	{`curl -sSu "$JIRA_USER:$T" x`, onlyT, `Send it on stdin instead: printf 'user = "%s:%s"\n' "$JIRA_USER" "$T" | curl -K - ...`},
	{`curl --user="me@example.com:$T" x`, onlyT, `Send it on stdin instead: printf 'user = "NAME:%s"\n' "$T" | curl -K - ...`},
	{`curl -H "X-SF-Token: $T" x`, onlyT, `Send it on stdin instead: printf 'header = "X-SF-Token: %s"\n' "$T" | curl -K - ...`},
	{`curl -H "Authorization: token $T" x`, onlyT, `Send it on stdin instead: printf 'header = "Authorization: token %s"\n' "$T" | curl -K - ...`},
	{`curl -H "X-Auth: scheme $T" x`, onlyT, `Send it on stdin instead: printf 'header = "X-Auth: ...%s"\n' "$T" | curl -K - ...`},
	{`curl -H 'X-Api-Key: '"$T" x`, onlyT, `Send it on stdin instead: printf 'header = "X-Api-Key: %s"\n' "$T" | curl -K - ...`},
	{`curl -H "X-Key-Prefix: ${T:0:8}" x`, onlyT, `Send it on stdin instead: printf 'header = "X-Key-Prefix: %s"\n' "${T...}" | curl -K - ...`},
	{`set -- 1 2 3 4 5 6 7 8 9 "$T"; curl -u "u:${10}" x`, onlyT, `Send it on stdin instead: printf 'user = "NAME:%s"\n' "${10}" | curl -K - ...`},
	{`H="Bearer $T"; curl -H "Authorization: $H" x`, onlyT, `Send it on stdin instead: printf 'header = "Authorization: %s"\n' "$H" | curl -K - ...`},
	{`curl -H "Authorization: Basic $(printf %s "u:$T" | base64)" x`, onlyT,
		`Send it on stdin instead: printf 'header = "Authorization: Basic %s"\n' "$(...)" | curl -K - ...`},
	{`curl -s "https://api.example.com/v1/items?api_key=$T"`, onlyT, `Send it on stdin instead: printf 'url = "...%s"\n' "$T" | curl -K - ...`},
	{`curl -d "{\"token\":\"$T\"}" x`, onlyT, `Send it on stdin instead: printf 'data = "...%s..."\n' "$T" | curl -K - ...`},
	{`curl -u "u:$T" -H "X-Api-Key: $T" x`, onlyT,
		`Send it on stdin instead: printf 'user = "NAME:%s"\nheader = "X-Api-Key: %s"\n' "$T" "$T" | curl -K - ...`},
	{`curl -u "u:$T" -H "X-Api-Key: $T" "https://api.example.com/?key=$T"`, onlyT,
		`Send it on stdin instead: printf 'user = "NAME:%s"\nheader = "X-Api-Key: %s"\nurl = "...%s"\n' "$T" "$T" "$T" | curl -K - ...`},
	// What xargs reads goes after the program's words, or in place of -I's {}.
	{`printf '%s' "$T" | xargs curl -u`, onlyT, `Send it on stdin instead: printf 'user = "%s"\n' "$T" | curl -K - ...`},
	{`printf '%s\n' "$T" | xargs -n1 curl -s`, onlyT, `Send it on stdin instead: printf 'url = "%s"\n' "$T" | curl -K - ...`},
	{`printf '%s\n' "$T" | xargs -I{} curl -H "X-Key: {}" x`, onlyT, `Send it on stdin instead: printf 'header = "X-Key: %s"\n' "$T" | curl -K - ...`},
	{`printf '%s' "$T" | xargs docker login -u bot -p`, onlyT, `Send it on stdin instead: printf '%s' "$T" | docker login --password-stdin ...`},
	{`printf '%s\n' "$T" | xargs -I{} mysql -u app -p{} -e "select 1"`, onlyT, `Pass it in the environment instead: MYSQL_PWD="$T" mysql ...`},
	{`printf '%s\n' "$T" | xargs psql`, onlyT, `Pass it in the environment instead: PGPASSWORD="$T" psql ...`},
	{`printf '%s\n' "$T" | xargs -n1 pg_dump`, onlyT, `Pass it in the environment instead: PGPASSWORD="$T" pg_dump ...`},
	{`mysql -u app -p"$T" -h db`, onlyT, `Pass it in the environment instead: MYSQL_PWD="$T" mysql ...`},
	{`psql "postgresql://app:$T@db.example.com/app"`, onlyT, `Pass it in the environment instead: PGPASSWORD="$T" psql ...`},
	{`pg_dump --password="$T" app`, onlyT, `Pass it in the environment instead: PGPASSWORD="$T" pg_dump ...`},
	{`docker run --rm -e GITHUB_TOKEN="$GITHUB_TOKEN" img`, []string{"GITHUB_TOKEN"},
		`Name the variable alone, so docker reads its value from its own environment: docker ... -e GITHUB_TOKEN ...`},
	{`docker run --env=API_KEY="$T" img`, onlyT,
		`Name the variable alone, and set it for docker, which reads its value from its own environment: API_KEY="$T" docker ... -e API_KEY ...`},
	{`docker login -u bot -p "$T" registry.example.com`, onlyT, `Send it on stdin instead: printf '%s' "$T" | docker login --password-stdin ...`},
	{`docker build --build-arg "KEY=$T" .`, onlyT, `Pass it to docker on stdin or in an environment variable it reads instead.`},
	{`docker run -e "$T" img`, onlyT, `Pass it to docker on stdin or in an environment variable it reads instead.`},
	{`git -c http.extraheader="Authorization: Bearer $GH_TOKEN" clone https://github.com/o/r`, []string{"GH_TOKEN"},
		`Pass it in git's environment instead: GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.extraheader GIT_CONFIG_VALUE_0="Authorization: Bearer $GH_TOKEN" git ...`},
	{`git -c "http.https://u:pw@git.example.com/.extraheader=Authorization: Bearer $T" fetch`, onlyT,
		`Pass it in git's environment instead: GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.https://...@git.example.com/.extraheader GIT_CONFIG_VALUE_0="Authorization: Bearer $T" git ...`},
	{`git clone "https://x-access-token:$GH_TOKEN@github.com/o/r.git"`, []string{"GH_TOKEN"},
		`Give it to git through a credential helper instead: git -c credential.helper='!f() { echo username=NAME; echo "password=$GH_TOKEN"; }; f' ...`},
	{`git clone "https://oauth2:$T@gitlab.example.com/o/r.git"`, onlyT,
		`Give it to git through a credential helper instead: git -c credential.helper='!f() { echo username=NAME; echo "password=$T"; }; f' ...`},
	{`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$T"`, onlyT,
		`Send it in a header that mcp-remote fills in from its environment instead, if the server takes one: npx -y mcp-remote ... --header 'Authorization: Bearer ${T}'`},
	{`npx -y mcp-remote@latest https://mcp.example.com/mcp --header "X-Key: $T"`, onlyT,
		`Let mcp-remote fill it in from its environment instead: npx -y mcp-remote ... --header 'X-Key: ${T}'`},
	// Each header keeps its own variable, and only a value in the URL needs a header.
	{`exec npx -y mcp-remote https://mcp.example.com/mcp --header "X-A: $A" --header "X-B: $B"`, []string{"A", "B"},
		`Let mcp-remote fill them in from its environment instead: npx -y mcp-remote ... --header 'X-A: ${A}' --header 'X-B: ${B}'`},
	{`exec npx -y mcp-remote "https://mcp.example.com/sse?key=$PD_KEY" --header "Authorization: Bearer $GITHUB_TOKEN"`, []string{"GITHUB_TOKEN", "PD_KEY"},
		`Let mcp-remote fill in GITHUB_TOKEN, PD_KEY from its environment instead, as it does each ${VAR} in a --header, with PD_KEY in a header, not its URL, if the server takes one: npx -y mcp-remote ... --header 'Authorization: Bearer ${GITHUB_TOKEN}'`},
	{`H="Bearer $T"; npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: $H"`, onlyT,
		`Let mcp-remote fill in T from its environment instead, as it does each ${VAR} in a --header.`},
	{`exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$A&secret=$B"`, []string{"A", "B"},
		`Let mcp-remote fill in A, B from its environment instead, as it does each ${VAR} in a --header, with A, B in headers, not its URL, if the server takes them.`},
	{`env API_TOKEN="$T" node app.js`, onlyT, `Set it in front of the command instead, which puts it in the environment only: API_TOKEN="$T" node ...`},
	{`sh -c 'printf "%s" "$1" | curl -K - x' _ "$T"`, onlyT, `Let sh read "$T" from its environment instead: sh -c '... "$T" ...'`},
	{`eval "curl -u u:$T x"`, onlyT, `Write the code in single quotes, so it reads "$T" only as it runs: eval '... "$T" ...'`},
	{`trap "curl -u u:$T x" EXIT`, onlyT, `Write the command in single quotes, so it reads "$T" only as it runs: trap '... "$T" ...' EXIT`},
	{`alias jc="curl -u u:$T"`, onlyT, `Write the alias in single quotes, so it reads "$T" only as it runs: alias NAME='... "$T" ...'`},
	{`grep -rl "$T" ./logs`, onlyT, `Pass it to grep on stdin or in an environment variable it reads instead.`},
}

func TestAdviceShowsTheProgramsOwnWayToTakeTheValue(t *testing.T) {
	for _, tc := range refusals {
		if got := advised(t, "sh", tc.script, tc.resolved); len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.script, got, tc.want)
		}
	}
}

// An MCP server's stdin carries the protocol, so its advice passes a value in
// the environment, or a header mcp-remote fills in, never on stdin.
func TestServerAdviceKeepsTheValueOffStdin(t *testing.T) {
	for _, tc := range []struct {
		script   string
		resolved []string
		want     string
	}{
		{`exec npx -y slack-mcp --token "$T"`, onlyT, `Pass it to npx in an environment variable it reads instead.`},
		{`curl -s -H "X-SF-Token: $T" x`, onlyT, `Let curl read it from its environment instead: curl --variable %T --expand-header 'X-SF-Token: {{T}}' ...`},
		{`curl -s -u "$JIRA_API_EMAIL:$JIRA_API_TOKEN" -H "X-Key: $JIRA_API_TOKEN" x`, jira,
			`Let curl read them from its environment instead: curl --variable %JIRA_API_EMAIL --variable %JIRA_API_TOKEN --expand-user '{{JIRA_API_EMAIL}}:{{JIRA_API_TOKEN}}' --expand-header 'X-Key: {{JIRA_API_TOKEN}}' ...`},
		{`H="Bearer $T"; curl -H "Authorization: $H" x`, onlyT, `Pass it to curl in an environment variable instead, which --variable reads.`},
		{`docker login -u bot -p "$T" registry.example.com`, onlyT, `Log docker in once, before the server starts, instead; docker keeps the login.`},
		{`printf '%s' "$T" | xargs curl -u`, onlyT, `Let curl read it from its environment instead: curl --variable %T --expand-user '{{T}}' ...`},
	} {
		found, err := shell.Check("sh", tc.script, tc.resolved)
		var got []string
		for _, f := range found {
			if line := shell.ServerAdvice(f, found); line != "" {
				got = append(got, line)
			}
		}
		if err != nil || len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s:\n got %q, %v\nwant %q", tc.script, got, err, tc.want)
		}
	}
	for _, tc := range refusals {
		found, _ := shell.Check("sh", tc.script, tc.resolved)
		for _, f := range found {
			if line := shell.ServerAdvice(f, found); strings.Contains(line, "stdin") || strings.Contains(line, "| ") {
				t.Errorf("%s: a server is told to read the value on stdin: %s", tc.script, line)
			}
		}
	}
}

// Findings of one command share one line, printed after the last of them;
// each other command gets its own.
func TestAdviceFollowsTheFindingsItFixes(t *testing.T) {
	found, err := shell.Check("sh", "curl -u \"$JIRA_API_EMAIL:$JIRA_API_TOKEN\" x\nmysql -p\"$JIRA_API_TOKEN\"", jira)
	if err != nil || len(found) != 3 {
		t.Fatalf("found %s, %v", brief(found), err)
	}
	var got []string
	for _, f := range found {
		got = append(got, shell.Advice(f, found))
	}
	if got[0] != "" || !strings.Contains(got[1], "printf 'user") || !strings.Contains(got[2], "MYSQL_PWD") {
		t.Errorf("advice in order: %q", got)
	}
}

// writtenWord is a fake credential of letters alone, which a word could be.
const writtenWord = "hunterpass"

// The safe form names variables and programs, but never shows what the script
// holds, which could be a credential written into it.
func TestAdviceNeverShowsWhatTheScriptHolds(t *testing.T) {
	for _, script := range []string{
		`curl -u "` + written + `@example.com:$T" x`,
		`curl -u "$T:` + written + `" x`,
		`curl -H "Authorization: Bearer ` + written + `$T" x`,
		`curl -H "X-Key: $T;` + written + `" x`,
		`curl -H "X-Auth: ` + writtenWord + ` $T" x`,
		`curl -H "` + written + `: $T" x`,
		`curl "https://` + written + `.example.com/?key=$T"`,
		`curl -d "user=` + written + `&token=$T" x`,
		`curl -H "Authorization: ${T:-` + written + `}" x`,
		`docker run -e "KEY=` + written + `$T" img`,
		`git -c "http.extraheader=X-Key: ` + written + ` $T" fetch`,
		`git -c "http.extraheader=X-Key: ` + writtenWord + ` $T" fetch`,
		`git -c "http.https://u:` + written + `@git.example.com/.extraheader=Authorization: Bearer $T" fetch`,
		`git -c "http.https://` + writtenWord + `@git.example.com/.extraheader=Authorization: Bearer $T" fetch`,
		`env "API_TOKEN=` + written + `$T" node app.js`,
		written + ` --token "$T"`,
		`printf '%s' "$T" | xargs ` + written,
		`printf '%s' "$T" | xargs -I{} curl -H "X-Key: ` + written + `{}" -u "` + writtenWord + `:{}" x`,
		`npx -y mcp-remote https://mcp.example.com/mcp --header "X-Key: ` + written + `$T" --header "` + written + `: $T"`,
		`npx -y mcp-remote "https://` + written + `.example.com/mcp?key=$T" --header "X-Auth: ` + writtenWord + ` $T"`,
	} {
		for _, line := range advised(t, "sh", script, onlyT) {
			if strings.Contains(line, written) || strings.Contains(line, writtenWord) {
				t.Errorf("%s: advice shows the script's text: %s", script, line)
			}
		}
	}
}

// Followed, the advice gives a command that keyward run would not refuse,
// with the words a real one has where the safe form shows ..., as $(jq ...)
// or $(cat FILE) in curl's URL or data, and in a loop or a pipeline; so does
// the advice for a server.
func TestFollowingTheAdviceLeavesNothingToRefuse(t *testing.T) {
	// What stands for an expansion in the script is a plain one.
	expansions := strings.NewReplacer("...}", "}", "$(...)", `$(printf %s "u:$T" | base64)`)
	for _, tc := range refusals {
		found, err := shell.Check("sh", tc.script, tc.resolved)
		if err != nil {
			t.Fatalf("%s: %v", tc.script, err)
		}
		for _, f := range found {
			for _, line := range []string{shell.Advice(f, found), shell.ServerAdvice(f, found)} {
				_, safe, ok := strings.Cut(line, ": ")
				if !ok {
					continue // advice that has no form to follow
				}
				safe = expansions.Replace(safe)
				slots := elided.FindAllStringSubmatchIndex(safe, -1)
				filled := false
				for _, words := range around[f.Program] {
					if len(words) != len(slots) {
						continue
					}
					filled = true
					form := safe
					for i := len(slots) - 1; i >= 0; i-- {
						form = form[:slots[i][2]] + words[i] + form[slots[i][3]:]
					}
					for _, wrap := range []string{"{}", "for id in 1 2 3; do {}; done", "{} | jq -r .key"} {
						script := strings.Replace(wrap, "{}", form, 1)
						if found, err := shell.Check("sh", script, tc.resolved); err != nil || len(found) > 0 {
							t.Errorf("%s: the safe form is refused as %s: %s, %v", tc.script, script, brief(found), err)
						}
					}
				}
				if !filled {
					t.Errorf("%s: no words to fill in the safe form %s", tc.script, safe)
				}
			}
		}
	}
}

// elided matches each ... that stands for a command's other words in a safe
// form, but not one in the text a form writes, as in url = "...%s".
var elided = regexp.MustCompile(`(?:^|[ '])(\.\.\.)(?:[ ']|$)`)

// around lists, by the program a safe form is for, the ways to fill in its
// ... in turn, with words a real command has there.
var around = map[string][][]string{
	"alias": {inScript},
	"curl": {
		{`-sS "https://jira.example.com/rest/api/3/search?jql=$(jq -rn --arg q 'project = DW' '$q|@uri')"`},
		{`-sS -X POST --data "$(jq -n --arg s 'Fix it' '{fields: {summary: $s}}')" https://jira.example.com/rest/api/3/issue`},
		{`-sS --data @body.json https://jira.example.com/rest/api/3/issue`},
		{`-sS -d "$(cat body.json)" https://jira.example.com/rest/api/3/issue`},
		{`-sS "$(head -n1 urls.txt)"`},
		{`-sS "$(sed -n 1p urls.txt)/comment/$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["id"])' issue.json)"`},
	},
	"docker":  {{`run --rm`, `ghcr.io/o/tool:1`}, {`-u "$(cat user.txt)" registry.example.com`}},
	"env":     {{`app.js --since "$(date +%F)"`}},
	"eval":    {inScript},
	"git":     {{`clone "https://github.com/$(cat repo.txt).git"`}},
	"mysql":   {{`-u app -h db.example.com -e "$(cat query.sql)"`}},
	"npx":     {{`https://mcp.example.com/mcp`}},
	"pg_dump": {{`-h db.example.com -U app -f "app-$(date +%F).sql" app`}},
	"psql":    {{`-h db.example.com -U app -c "$(cat query.sql)"`}},
	"sh":      {inScript},
	"trap":    {inScript},
}

// inScript fills in code in single quotes, around the variable it reads.
var inScript = []string{`printf "header = \"X-Key: %s\"\n"`, `| curl -sK - "$(cat url.txt)"`}
