package shell_test

import (
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veilux-lab/keyward/internal/shell"
)

const (
	refuse = true
	allow  = false
)

var (
	onlyT = []string{"T"}
	jira  = []string{"JIRA_API_EMAIL", "JIRA_API_TOKEN"}
)

// written is a fake credential written into a script, which the check never
// shows.
const written = "Kq7pL2xV9mN4"

// scripts are what keyward run might be given to run as shell -c script,
// with the variables it resolves, each checked on real shells with fake
// values.
var scripts = []struct {
	name, shell, script string
	resolved            []string
	refuse              bool
}{
	// The incident: sh expands both values into curl's command line.
	{"jira-basic-u", "sh", `curl -s -u "$JIRA_API_EMAIL:$JIRA_API_TOKEN" -H "Accept: application/json" "$1/rest/api/3/myself"`, jira, refuse},
	// A header is an argument like any other.
	{"signalfx-header", "sh", `curl -s -H "X-SF-Token: $SIGNALFX_API_TOKEN" "https://api.us0.signalfx.com/v2/detector" -o ./det.json`, []string{"SIGNALFX_API_TOKEN"}, refuse},
	// printf is a builtin, so the value reaches only the pipe that curl -K - reads.
	{"printf-config-stdin", "sh", `printf 'header = "Authorization: Bearer %s"\n' "$SONAR_TOKEN" | curl -sS -K - "https://sonar.example.com/api/issues/search?ps=1"`, []string{"SONAR_TOKEN"}, allow},
	// gh reads GH_TOKEN from its environment, and the script never expands it.
	{"gh-reads-env", "sh", `gh api repos/o/r/pulls --jq '.[].title'; gh pr view 1 --repo o/r --json state`, []string{"GH_TOKEN"}, allow},
	// A helper function: its body is read, and the call passes it no value.
	{"function-wrapper", "sh", `B=https://sonar.example.com/api; g() { printf 'header = "Authorization: Bearer %s"\n' "$SONAR_TOKEN" | curl -sS -K - "$B/$1"; }; g "issues/search?ps=1" > ./out.json`, []string{"SONAR_TOKEN"}, allow},
	// $n holds build numbers from curl's response, not the token.
	{"loop-over-response", "sh", `B=https://jenkins.example.com/job/x; for n in $(printf 'user = "u:%s"\n' "$JENKINS_AUTH_TOKEN" | curl -sS -K - "$B/api/json" | python3 -I -c 'import json,sys;print(" ".join(str(b["number"]) for b in json.load(sys.stdin)["builds"]))'); do printf 'user = "u:%s"\n' "$JENKINS_AUTH_TOKEN" | curl -sS -K - "$B/$n/consoleText" -o "./b-$n.txt"; done`, []string{"JENKINS_AUTH_TOKEN"}, allow},
	// c holds curl's HTTP status, not the token.
	{"status-code-capture", "sh", `c=$(printf 'user = "u:%s"\n' "$JENKINS_AUTH_TOKEN" | curl -s -o /dev/null -w "%{http_code}" -K - "$1"); curl -s "https://status.example.com/report?code=$c"`, []string{"JENKINS_AUTH_TOKEN"}, allow},
	// base64 and tr read the value on stdin, and only printf, a builtin, gets their output.
	{"basic-auth-via-builtin", "sh", `printf 'header = "Authorization: Basic %s"\n' "$(printf "%s:%s" "$JIRA_API_EMAIL" "$JIRA_API_TOKEN" | base64 | tr -d "\n")" | curl -s -K - "https://jira.example.com/rest/api/3/myself"`, jira, allow},
	// base64 is reversible, so the encoded copy is the secret.
	{"derived-base64-in-argv", "sh", `AUTH=$(printf "%s" "u:$T" | base64); curl -s -H "Authorization: Basic $AUTH" https://x.example.com`, onlyT, refuse},
	// git gets the text $GH_TOKEN; the helper's shell expands it, and echo writes it to git's pipe.
	{"git-helper-escaped-dollar", "sh", `git -c credential.helper= -c credential.helper="!f(){ echo username=x; echo password=\$GH_TOKEN; }; f" fetch -q origin pull/1/head`, []string{"GH_TOKEN"}, allow},
	// python reads the value from its environment; what python -c does is out of scope.
	{"python-reads-environ", "sh", `python3 -I -c "import json,os; print(json.dumps({\"pat\": os.environ[\"CORONA_PAT\"]}))" | curl -s --data @- https://corona.example.com/api/auth/sign_in`, []string{"CORONA_PAT"}, allow},
	// Not resolved, GITHUB_TOKEN holds only its cap:// reference.
	{"only-excludes-variable", "sh", `curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user`, []string{"GH_TOKEN"}, allow},
	// Without --only, every variable that holds a reference is resolved.
	{"no-only-resolves-all", "sh", `gh pr list --repo o/r; curl -s -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user`, []string{"GH_TOKEN", "GITHUB_TOKEN", "JIRA_API_TOKEN"}, refuse},
	// A path runs the program, not the builtin.
	{"absolute-printf", "sh", `/usr/bin/printf 'header = "X-Api-Key: %s"\n' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// command runs the builtin in sh, bash and dash.
	{"command-printf-sh", "sh", `command printf 'header = "X-Api-Key: %s"\n' "$T" | curl -sK - https://x.example.com`, onlyT, allow},
	// zsh's command runs the program, not the builtin.
	{"command-printf-zsh", "zsh", `command printf 'header = "X-Api-Key: %s"\n' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// So does zsh's command -p.
	{"command-p-printf-zsh", "zsh", `command -p printf 'header = "X-Api-Key: %s"\n' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// exec runs only programs in sh, bash and dash.
	{"exec-printf-sh", "sh", `exec printf '%s' "$T"`, onlyT, refuse},
	// zsh's exec runs a builtin, then exits.
	{"exec-printf-zsh", "zsh", `exec printf '%s' "$T"`, onlyT, allow},
	// builtin runs the builtin.
	{"builtin-printf-bash", "bash", `builtin printf 'header = "X-Api-Key: %s"\n' "$T" | curl -sK - https://x.example.com`, onlyT, allow},
	// Quoting a command's name only stops alias expansion: the builtin still runs.
	{"quoted-command-name", "sh", `\printf '%s' "$T" | curl -sK - https://x.example.com; "printf" '%s' "$T" | curl -sK - https://x.example.com`, onlyT, allow},
	// Refused, though the script is safe: $p could name anything, so it is taken for a program.
	{"variable-command-name", "sh", `p=printf; $p '%s' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// dash has no time keyword, so /usr/bin/time runs printf, the program.
	{"time-printf-dash", "dash", `time printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// time is a keyword in bash, so the builtin runs.
	{"time-printf-bash", "bash", `time printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, allow},
	// A function named printf runs instead of the builtin and passes its words to /usr/bin/printf.
	{"function-shadows-printf", "sh", `printf() { /usr/bin/printf "$@"; }; printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// sh expands an alias the script defines, from the next line on.
	{"alias-shadows-printf-sh", "sh", "alias printf=/usr/bin/printf\nprintf '%s' \"$T\" | curl -sK - https://x.example.com", onlyT, refuse},
	// bash -c expands no alias without shopt -s expand_aliases.
	{"alias-shadows-printf-bash", "bash", "alias printf=/usr/bin/printf\nprintf '%s' \"$T\" | curl -sK - https://x.example.com", onlyT, allow},
	// enable -n turns the builtin off, so printf is the program.
	{"enable-n-printf", "bash", `enable -n printf; printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// zsh's disable does the same.
	{"zsh-disable-printf", "zsh", `disable printf; printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// zsh's =printf expands to the program's path.
	{"zsh-equals-command", "zsh", `=printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// print is a builtin only in zsh.
	{"print-outside-zsh", "sh", `print -r -- "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// print is a zsh builtin.
	{"zsh-print-r", "zsh", `print -r -- "header = \"Authorization: Bearer $T\"" | curl -sK - https://x.example.com`, onlyT, allow},
	// echo is a builtin in every shell.
	{"echo-builtin-dash", "dash", `echo "$T" | curl -sK - https://x.example.com`, onlyT, allow},
	// test and [ are builtins.
	{"test-and-bracket", "sh", `[ -n "$T" ] && test "$T" != changeme && [ "${#T}" -gt 20 ] && curl -s https://x.example.com`, onlyT, allow},
	// zsh's command runs /bin/[ with the value.
	{"command-bracket-zsh", "zsh", `command [ -n "$T" ] && curl -s https://x.example.com`, onlyT, refuse},
	// [[ is a keyword.
	{"double-bracket", "bash", `[[ $T == ghp_* ]] || curl -s https://x.example.com`, onlyT, allow},
	// expr is a program in every shell.
	{"expr-external", "sh", `expr "$T" : "ghp_" >/dev/null || curl -s https://x.example.com`, onlyT, refuse},
	// All builtins.
	{"colon-true-kill", "sh", `: "$T"; true "$T"; kill -0 "$T" 2>/dev/null; type "$T" >/dev/null 2>&1; curl -s https://x.example.com`, onlyT, allow},
	// env's NAME=value is a word of env's command line, though it ends in node's environment.
	{"env-assignment", "sh", `env API_TOKEN="$T" node app.js`, onlyT, refuse},
	// The shell puts a prefix assignment in the program's environment.
	{"prefix-assignment", "sh", `API_TOKEN="$T" node app.js`, onlyT, allow},
	// So does exec.
	{"prefix-assignment-exec", "sh", `MAPPING_TOKEN="$T" exec python3 -I ./e2e.py`, onlyT, allow},
	// env -i clears the environment, but the value it adds back is in env's command line.
	{"env-i-with-value", "sh", `env -i PATH=/usr/bin:/bin API_TOKEN="$T" node app.js`, onlyT, refuse},
	// env -u and env -i take T away, so the inner sh's $T is empty.
	{"env-i-or-u-drops-value", "sh", `env -u T node app.js; env -i PATH=/usr/bin:/bin sh -c 'curl -s -u "u:$T" https://x.example.com'`, onlyT, allow},
	// nohup's command line and curl's both hold the value.
	{"nohup-curl", "sh", `nohup curl -s -u "u:$T" https://x.example.com >/dev/null 2>&1`, onlyT, refuse},
	// A launcher runs printf, the program.
	{"timeout-printf", "sh", `timeout 5 printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, refuse},
	// The inner sh inherits T and gives it to printf, the builtin.
	{"timeout-nested-safe", "sh", `timeout 30 sh -c 'printf "%s" "$T" | curl -sK - https://x.example.com'`, onlyT, allow},
	// sudo's command line holds the value, and sudo logs it.
	{"sudo-curl", "sh", `sudo curl -s -u "u:$T" https://x.example.com`, onlyT, refuse},
	// watch runs its words as an sh script, with T inherited.
	{"watch-nested-leak", "sh", `watch -n 5 'curl -s -u "u:$T" https://x.example.com'`, onlyT, refuse},
	// Read as a script, it is the safe form.
	{"watch-nested-safe", "sh", `watch -n 5 'printf "%s" "$T" | curl -sK - https://x.example.com'`, onlyT, allow},
	// curl gets the value, whatever runs it.
	{"time-curl", "bash", `time curl -s -u "u:$T" https://x.example.com`, onlyT, refuse},
	// Launchers that take a command: their command lines and curl's hold the value.
	{"caffeinate-and-script", "sh", `caffeinate -i curl -s -u "u:$T" https://x.example.com; script -q /dev/null curl -s -u "u:$T" https://y.example.com`, onlyT, refuse},
	// The inner script is safe, but the value is a word of the inner sh's command line.
	{"nested-sh-positional", "sh", `sh -c 'printf "%s" "$1" | curl -sK - https://x.example.com' _ "$T"`, onlyT, refuse},
	// The inner sh reads T from its environment.
	{"nested-sh-env-safe", "sh", `sh -c 'printf "%s" "$T" | curl -sK - https://x.example.com'`, onlyT, allow},
	// The outer sh expands the value into the inner sh's script, a word of its command line.
	{"nested-sh-double-quoted", "sh", `sh -c "curl -s -u u:$T https://x.example.com"`, onlyT, refuse},
	// The inner script expands T, which it inherits, into curl's command line.
	{"nested-sh-single-quoted-leak", "sh", `bash -c 'curl -s -u "u:$T" https://x.example.com'`, onlyT, refuse},
	// X is not exported, so the inner $X is empty.
	{"nested-unexported-copy", "sh", `X=$T; sh -c 'curl -s -u "u:$X" https://x.example.com'`, onlyT, allow},
	// set -a exports X, so the inner shell expands the copy.
	{"nested-allexport-copy", "sh", `set -a; X=$T; sh -c 'curl -s -u "u:$X" https://x.example.com'`, onlyT, refuse},
	// An sh -c script among another program's words runs with T inherited.
	{"find-exec-sh", "sh", `find . -maxdepth 0 -exec sh -c 'curl -s -u "u:$T" -T "$1" https://x.example.com' _ {} \;`, onlyT, refuse},
	// A shell that reads its script from stdin would run the value as code.
	{"heredoc-into-sh", "sh", "sh <<EOF\ncurl -s -u \"u:$T\" https://x.example.com\nEOF", onlyT, refuse},
	// Under a quoted delimiter, the inner sh expands $T itself.
	{"quoted-heredoc-into-sh", "sh", "sh <<'EOF'\ncurl -s -u \"u:$T\" https://x.example.com\nEOF", onlyT, refuse},
	// The inner script reads the value from stdin into v.
	{"pipe-into-sh-read", "sh", `printf '%s\n' "$T" | sh -c 'read -r v; curl -s -u "u:$v" https://x.example.com'`, onlyT, refuse},
	// xargs makes what it reads into curl's words.
	{"xargs-from-pipe", "sh", `printf '%s' "$T" | xargs -I{} curl -s -u "u:{}" https://x.example.com`, onlyT, refuse},
	// The same from a here-string.
	{"xargs-from-herestring", "bash", `xargs curl -s -u <<<"u:$T"`, onlyT, refuse},
	// The same into mysql's words.
	{"xargs-into-mysql", "sh", `printf '%s\n' "$DB_PASSWORD" | xargs -I{} mysql -u app -p{} -e "select 1"`, []string{"DB_PASSWORD"}, refuse},
	// read copies the value into v.
	{"read-herestring", "bash", `read -r v <<<"$T"; curl -s -u "u:$v" https://x.example.com`, onlyT, refuse},
	// zsh runs a pipeline's last command in the current shell, so v is set.
	{"pipe-into-read-zsh", "zsh", `printf '%s\n' "$T" | read -r v; curl -s -u "u:$v" https://x.example.com`, onlyT, refuse},
	// sh runs it in a subshell, so v is empty; refused anyway, as the script means to pass the value.
	{"pipe-into-read-sh", "sh", `printf '%s\n' "$T" | read -r v; curl -s -u "u:$v" https://x.example.com`, onlyT, refuse},
	// The loop reads each line into h.
	{"while-read-loop", "sh", `printf 'Authorization: Bearer %s\n' "$T" | while read -r h; do curl -s -H "$h" https://x.example.com; done`, onlyT, refuse},
	// $(cat) reads the group's stdin, the here-document.
	{"cat-sub-in-group", "sh", "{ curl -s -u \"u:$(cat)\" https://x.example.com; } <<EOF\n$T\nEOF", onlyT, refuse},
	// Words expand before the command's own redirections, so $(cat) reads the script's stdin.
	{"cat-sub-own-redirect", "sh", "curl -s -u \"u:$(cat)\" https://x.example.com <<EOF\n$T\nEOF", onlyT, allow},
	// exec 3<<EOF keeps fd 3 open on the value for a later $(cat <&3).
	{"exec-fd-then-cat-sub", "sh", "exec 3<<EOF\n$T\nEOF\ncurl -s -u \"u:$(cat <&3)\" https://x.example.com", onlyT, refuse},
	// curl reads the value from /dev/fd/3, and its command line holds only the path.
	{"exec-fd-config-safe", "bash", `exec 3<<<"header = \"Authorization: Bearer $T\""; curl -s -K /dev/fd/3 https://x.example.com`, onlyT, allow},
	// getopts copies its argument into OPTARG.
	{"getopts-optarg", "sh", `getopts t: o -t "$T"; curl -s -u "u:$OPTARG" https://x.example.com`, onlyT, refuse},
	// Pieces of the value are still the value.
	{"ifs-read-split", "dash", "IFS=: read -r user pass <<EOF\n$T\nEOF\ncurl -s -u \"$user:$pass\" https://x.example.com", onlyT, refuse},
	// set -- makes the value $1.
	{"set-positional", "sh", `set -- "$T"; curl -s -u "u:$1" https://x.example.com`, onlyT, refuse},
	// "$@" expands every parameter.
	{"set-positional-at", "dash", `set -- -u "u:$T"; curl -s "$@" https://x.example.com`, onlyT, refuse},
	// $1 reaches only printf, the builtin.
	{"set-positional-safe-use", "sh", `set -- "$T"; printf '%s' "$1" | curl -sK - https://x.example.com`, onlyT, allow},
	// An array element holds the value.
	{"bash-array", "bash", `args=(-H "Authorization: Bearer $T"); curl -s "${args[@]}" https://x.example.com`, onlyT, refuse},
	// zsh expands $a to every element.
	{"zsh-array-unquoted", "zsh", `a=(-u "u:$T"); a+=(-H "X: $T"); curl -s $a https://x.example.com`, onlyT, refuse},
	// A function's body puts its $1 in curl's command line.
	{"function-positional", "sh", `auth() { curl -s -u "u:$1" "$2"; }; auth "$T" https://x.example.com`, onlyT, refuse},
	// The body never runs.
	{"function-never-called", "sh", `f() { curl -s -u "u:$T" https://x.example.com; }; curl -s https://y.example.com`, onlyT, allow},
	// eval runs its text as script.
	{"eval-literal", "sh", `eval 'curl -s -u "u:$T" https://x.example.com'`, onlyT, refuse},
	// eval of text that holds the value runs the value as code.
	{"eval-generated", "sh", `eval "$(printf 'curl -s -u u:%s https://x.example.com' "$T")"`, onlyT, refuse},
	// eval of output that holds no value.
	{"eval-untainted-dynamic", "sh", `eval "$(ssh-agent -s)" >/dev/null; printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, allow},
	// trap's command runs later as script.
	{"trap-single-quoted", "sh", `trap 'curl -s -u "u:$T" https://x.example.com' EXIT; :`, onlyT, refuse},
	// A trap that never touches the value.
	{"trap-cleanup", "sh", `f=$(mktemp); trap 'rm -f "$f"' EXIT; printf '%s' "$T" | curl -sK - https://x.example.com -o "$f"`, onlyT, allow},
	// The shell matches a case word itself.
	{"case-on-value", "sh", `case "$T" in ghp_*) printf 'header = "Authorization: token %s"\n' "$T" | curl -sK - https://api.github.com/user;; *) echo "not a classic token";; esac`, onlyT, allow},
	// The loop variable is a copy.
	{"for-loop-copy", "sh", `for t in "$T"; do curl -s -u "u:$t" https://x.example.com; done`, onlyT, refuse},
	// A loop over names that uses only a length.
	{"for-over-names", "sh", `for v in JIRA_API_TOKEN T; do printf '%s=%s\n' "$v" "${#T}"; done`, onlyT, allow},
	// ${#T} is a number.
	{"length-only", "sh", `curl -s -H "X-Token-Length: ${#T}" https://x.example.com`, onlyT, allow},
	// ${T:+yes} is the word yes.
	{"alternate-constant", "sh", `curl -s "https://x.example.com/?auth=${T:+yes}"`, onlyT, allow},
	// ${T:-x} is the value when it is set.
	{"default-value", "sh", `curl -s "https://x.example.com/?k=${T:-none}"`, onlyT, refuse},
	// A resolved variable in another's default.
	{"default-from-value", "sh", `curl -s -u "u:${TOKEN_OVERRIDE:-$T}" https://x.example.com`, onlyT, refuse},
	// Most of the value is still the value.
	{"suffix-prefix-strip", "sh", `curl -s "https://x.example.com/?a=${T%?}&b=${T#ghp_}"`, onlyT, refuse},
	// So is part of it.
	{"substring", "bash", `curl -s "https://x.example.com/?prefix=${T:0:8}"`, onlyT, refuse},
	// A numeric secret, such as a PIN, survives arithmetic.
	{"arithmetic-numeric-secret", "sh", `curl -s "https://x.example.com/?pin=$((PIN + 0))"`, []string{"PIN"}, refuse},
	// Arithmetic on a length is a number.
	{"arithmetic-on-length", "sh", `[ $(( ${#T} )) -gt 20 ] && curl -s https://x.example.com`, onlyT, allow},
	// ${!n} reads T under another name.
	{"bash-indirect", "bash", `n=T; curl -s -u "u:${!n}" https://x.example.com`, onlyT, refuse},
	// So does zsh's ${(P)n}.
	{"zsh-P-flag", "zsh", `n=T; curl -s -u "u:${(P)n}" https://x.example.com`, onlyT, refuse},
	// $T_URL and $Tx are other variables.
	{"name-boundary", "sh", `curl -s "https://x.example.com/$T_URL/$Tx"`, onlyT, allow},
	// A comment does not run.
	{"comment-mentions-value", "sh", "# never do: curl -u \"u:$T\"\nprintf '%s' \"$T\" | curl -sK - https://x.example.com", onlyT, allow},
	// How mcp wrap writes a header: mcp-remote fills in ${PD_KEY} from its own environment.
	{"mcp-wrap-header-literal", "sh", `exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer "'$''{PD_KEY}'"" --transport http-only`, []string{"PD_KEY"}, allow},
	// What mcp wrap --allow-command-line writes for a key in a URL.
	{"mcp-wrap-allowed-url", "sh", `exec npx -y mcp-remote "https://mcp.example.com/sse?key=$PD_KEY" --transport sse-only`, []string{"PD_KEY"}, refuse},
	// curl gets the text $T.
	{"single-quoted-literal", "sh", `curl -s -H 'Authorization: Bearer $T' https://x.example.com`, onlyT, allow},
	// \$ in double quotes is a dollar sign.
	{"escaped-dollar", "sh", `curl -s -H "Authorization: Bearer \$T" https://x.example.com`, onlyT, allow},
	// $'...' expands nothing.
	{"ansi-c-quote", "bash", `curl -s -H $'Authorization: Bearer $T\t' https://x.example.com`, onlyT, allow},
	// $"..." expands as double quotes do.
	{"locale-double-quote", "bash", `curl -s -H $"Authorization: Bearer $T" https://x.example.com`, onlyT, refuse},
	// curl fills in {{T}} from its own environment.
	{"curl-variable-expand", "sh", `curl -s --variable %T --expand-header 'Authorization: Bearer {{T}}' https://x.example.com`, onlyT, allow},
	// $T in single quotes is jq's and awk's own syntax.
	{"dollar-in-other-programs-syntax", "sh", `jq -r '.items[] | "\(.name) $T"' ./items.json; awk '{print $T}' ./f`, onlyT, allow},
	// docker -e NAME reads the value from docker's environment.
	{"docker-env-name-only", "sh", `docker run --rm -e GITHUB_TOKEN ghcr.io/o/tool:1`, []string{"GITHUB_TOKEN"}, allow},
	// -e NAME=value is a word of docker's command line.
	{"docker-env-name-value", "sh", `docker run --rm -e GITHUB_TOKEN="$GITHUB_TOKEN" ghcr.io/o/tool:1`, []string{"GITHUB_TOKEN"}, refuse},
	// --password-stdin reads the pipe.
	{"docker-login-stdin", "sh", `printf '%s' "$T" | docker login -u bot --password-stdin registry.example.com`, onlyT, allow},
	// git -c is a word of git's command line.
	{"git-extraheader", "sh", `git -c http.extraheader="Authorization: Bearer $GH_TOKEN" clone https://github.com/o/r`, []string{"GH_TOKEN"}, refuse},
	// The same setting in git's environment.
	{"git-config-env", "sh", `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=http.extraheader GIT_CONFIG_VALUE_0="Authorization: Bearer $GH_TOKEN" git clone https://github.com/o/r`, []string{"GH_TOKEN"}, allow},
	// A token in a URL is a word of git's command line.
	{"git-url-token", "sh", `git clone "https://x-access-token:$GH_TOKEN@github.com/o/r.git"`, []string{"GH_TOKEN"}, refuse},
	// Process substitution gives curl a path.
	{"curl-config-procsub", "bash", `curl -s --config <(printf 'header = "Authorization: Bearer %s"\n' "$T") https://x.example.com`, onlyT, allow},
	// mysql hides its password once it starts, after exec logging recorded it.
	{"mysql-p-value", "sh", `mysql -u app -p"$DB_PASSWORD" -h db.example.com -e "select 1"`, []string{"DB_PASSWORD"}, refuse},
	// Environment only.
	{"mysql-pwd-env", "sh", `MYSQL_PWD="$DB_PASSWORD" mysql -u app -h db.example.com -e "select 1"`, []string{"DB_PASSWORD"}, allow},
	// Environment only.
	{"pgpassword-env", "sh", `PGPASSWORD="$DB_PASSWORD" psql -h db.example.com -U app -c "select 1"`, []string{"DB_PASSWORD"}, allow},
	// A password in a URL is a word of psql's command line.
	{"psql-url-password", "sh", `psql "postgresql://app:$DB_PASSWORD@db.example.com/app"`, []string{"DB_PASSWORD"}, refuse},
	// So is a key in a URL.
	{"url-query-key", "sh", `curl -s "https://api.example.com/v1/items?api_key=$API_KEY"`, []string{"API_KEY"}, refuse},
	// jq --arg is a word of jq's command line.
	{"jq-arg", "sh", `jq -n --arg t "$T" '{token: $t}' | curl -s --data @- https://x.example.com`, onlyT, refuse},
	// jq prints T from its environment into curl's command line.
	{"jq-env-subst", "sh", `curl -s -H "Authorization: Bearer $(jq -rn 'env.T')" https://x.example.com`, onlyT, refuse},
	// So does printenv.
	{"printenv-subst", "sh", `curl -s -H "X-SF-Token: $(printenv SIGNALFX_API_TOKEN)" https://api.us0.signalfx.com/v2/detector`, []string{"SIGNALFX_API_TOKEN"}, refuse},
	// gh auth token prints GH_TOKEN.
	{"gh-auth-token-subst", "sh", `curl -s -H "Authorization: Bearer $(gh auth token)" https://api.github.com/user`, []string{"GH_TOKEN"}, refuse},
	// awk -v is a word of awk's command line.
	{"awk-v", "sh", `awk -v t="$T" 'BEGIN { print length(t) }'`, onlyT, refuse},
	// Searching for a value puts it in grep's command line.
	{"grep-for-value", "sh", `grep -rl "$T" ./logs`, onlyT, refuse},
	// An interpreter's argument is a word of its command line.
	{"python-argv", "sh", `python3 -I -c 'import sys; print(len(sys.argv[1]))' "$T"`, onlyT, refuse},
	// security takes the password only as an argument.
	{"security-w", "sh", `security add-generic-password -a me -s svc -w "$T"`, onlyT, refuse},
	// pass:$T is an argument, and env:T is text.
	{"openssl-pass", "sh", `openssl enc -aes-256-cbc -pbkdf2 -pass pass:"$T" -in ./f -out ./f.enc; openssl enc -aes-256-cbc -pbkdf2 -pass env:T -in ./f -out ./g.enc`, onlyT, refuse},
	// --from-literal is a word of kubectl's command line.
	{"kubectl-from-literal", "sh", `kubectl create secret generic s --from-literal=token="$T"`, onlyT, refuse},
	// launchctl's command line holds the value.
	{"launchctl-setenv", "sh", `launchctl setenv API_TOKEN "$T"`, onlyT, refuse},
	// osascript's command line holds the value.
	{"osascript-shell", "sh", `osascript -e "do shell script \"curl -s -u u:$T https://x.example.com\""`, onlyT, refuse},
	// ssh's command line holds the value.
	{"ssh-remote-command", "sh", `ssh host.example.com "curl -s -u u:$T https://x.example.com"`, onlyT, refuse},
	// exec -a makes the value the program's first word.
	{"exec-argv0", "bash", `exec -a "$T" sleep 1`, onlyT, refuse},
	// exec with only redirections starts no program.
	{"exec-redirect-only", "sh", `exec 2>/dev/null; printf '%s' "$T" | curl -sK - https://x.example.com`, onlyT, allow},
	// stdin only.
	{"herestring-to-stdin", "bash", `jq -R . <<<"$T" >/dev/null; base64 <<<"$T" >/dev/null`, onlyT, allow},
	// printf -v writes a copy into h.
	{"printf-v-copy", "bash", `printf -v h 'Bearer %s' "$T"; curl -s -H "Authorization: $h" https://x.example.com`, onlyT, refuse},
	// Copies through readonly and local.
	{"readonly-local-copy", "sh", `readonly R="$T"; f() { local L="$R"; curl -s -u "u:$L" https://x.example.com; }; f`, onlyT, refuse},
	// Backquotes are $(...).
	{"backtick-subst", "sh", "curl -s -u \"u:`printf %s \"$T\"`\" https://x.example.com", onlyT, refuse},
	// cat copies a here-document that holds the value.
	{"heredoc-in-subst", "sh", "v=$(cat <<EOF\n$T\nEOF\n)\ncurl -s -u \"u:$v\" https://x.example.com", onlyT, refuse},
	// Only the length leaves the pipeline.
	{"length-via-wc", "sh", `n=$(printf '%s' "$T" | wc -c); curl -s -H "X-Len: $n" https://x.example.com`, onlyT, allow},
	// Refused, though T no longer holds the value: what a variable may hold only grows, so T=placeholder keeps it too.
	{"reassigned-constant", "sh", `T=placeholder; curl -s -u "u:$T" https://x.example.com`, onlyT, refuse},
	// An assignment in ( ) ends with the subshell.
	{"subshell-copy-does-not-escape", "sh", `(X=$T); curl -s -u "u:$X" https://x.example.com`, onlyT, allow},
	// A token minted with the value reaches curl through a file, which no check of the script can follow.
	{"minted-token-through-file", "sh", `printf 'header = "Authorization: Basic %s"\n' "$CLIENT_CREDS" | curl -s -K - -X POST https://idp.example.com/token -o ./tok.json; AT=$(jq -r .access_token ./tok.json); curl -s -H "Authorization: Bearer $AT" http://localhost:8083/api`, []string{"CLIENT_CREDS"}, allow},
	// A file is no command line.
	{"tee-to-file", "sh", `printf '%s' "$T" | tee ./token.txt >/dev/null`, onlyT, allow},
	// Nor is a config file written from a here-document.
	{"heredoc-to-file", "sh", "cat > ./curl.cfg <<EOF\nheader = \"Authorization: Bearer $T\"\nEOF\ncurl -s -K ./curl.cfg https://x.example.com", onlyT, allow},
	// tee's file name is a word of its command line.
	{"value-as-file-name", "sh", `printf x | tee "./$T" >/dev/null; rm -f "./$T"`, onlyT, refuse},
	// zsh's =(...) gives curl a path.
	{"zsh-equals-tempfile", "zsh", `curl -s -K =(print -r -- "header = \"Authorization: Bearer $T\"") https://x.example.com`, onlyT, allow},
	// A backslash and a newline join the lines into one command.
	{"line-continuation", "sh", "curl -s \\\n  -H \"Accept: application/json\" \\\n  -u \"u:$T\" \\\n  https://x.example.com", onlyT, refuse},
	// Commands inside if, while, { }, ( ) and & have command lines too.
	{"compound-commands", "sh", `if curl -s -u "u:$T" https://x.example.com; then :; fi; while ! curl -s -u "u:$T" https://y.example.com; do break; done; { curl -s -u "u:$T" https://z.example.com; }; ( curl -s -u "u:$T" https://w.example.com ) & wait`, onlyT, refuse},
	// The function NAME { ...; } form.
	{"ksh-style-function", "bash", `function f { curl -s -u "u:$T" https://x.example.com; }; f`, onlyT, refuse},
	// A nameref reads T under another name.
	{"bash-nameref", "bash", `declare -n r=T; curl -s -u "u:$r" https://x.example.com`, onlyT, refuse},
	// curl -H @- reads headers from stdin.
	{"curl-header-from-stdin", "sh", `printf 'Authorization: Bearer %s\n' "$T" | curl -s -H @- https://x.example.com`, onlyT, allow},
	// A request body is an argument too.
	{"curl-data-in-argv", "sh", `curl -s -d "{\"token\":\"$T\"}" https://x.example.com/login`, onlyT, refuse},
	// curl -d @- reads it from stdin.
	{"curl-data-from-stdin", "sh", `printf '{"token":"%s"}' "$T" | curl -s -d @- https://x.example.com/login`, onlyT, allow},
	// set -x prints the value on stderr, but in no command line.
	{"xtrace-prints-value", "sh", `set -x; printf 'header = "Authorization: Bearer %s"\n' "$T" | curl -sK - https://x.example.com`, onlyT, allow},
}

func TestCheckRefusesAScriptThatPutsAValueInACommandLine(t *testing.T) {
	for _, tc := range scripts {
		found, err := shell.Check(tc.shell, tc.script, tc.resolved)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got := len(found) > 0; got != tc.refuse {
			t.Errorf("%s: refused = %v, want %v; found %s", tc.name, got, tc.refuse, brief(found))
		}
	}
}

// commandLines are keyward run's command lines, as an agent's shell would
// split them, with the variables that keyward run resolves and those whose
// values the check should find in a command line.
var commandLines = []struct {
	name           string
	argv, resolved []string
	want           []string
}{
	{"leak: Jira -u", []string{`sh`, `-c`, `curl -s -u "$JIRA_API_EMAIL:$JIRA_API_TOKEN" "$1"`, `_`, `$URL`}, []string{"JIRA_API_EMAIL", "JIRA_API_TOKEN"}, []string{"JIRA_API_EMAIL", "JIRA_API_TOKEN"}},
	{"safe: printf to curl -K", []string{`sh`, `-c`, `printf "header = \"Authorization: Bearer %s\"\n" "$API_TOKEN" | curl -sS -K - "$1"`, `_`, `$URL`}, []string{"API_TOKEN"}, nil},
	{"leak: -H SignalFx", []string{`sh`, `-c`, `curl -s -H "X-SF-Token: $SIGNALFX_API_TOKEN" "$1" -o /tmp/out.json`, `_`, `https://x`}, []string{"SIGNALFX_API_TOKEN"}, []string{"SIGNALFX_API_TOKEN"}},
	{"leak: derived var", []string{`sh`, `-c`, `AUTH=$(printf %s "u:$T" | base64); curl -H "Authorization: Basic $AUTH" https://x`}, []string{"T"}, []string{"T"}},
	{"leak: command substitution", []string{`sh`, `-c`, `curl -H "Authorization: Basic $(printf %s "u:$T" | base64)" https://x`}, []string{"T"}, []string{"T"}},
	{"safe: heredoc to stdin", []string{`sh`, `-c`, "curl -K - https://x <<EOF\nheader = \"Authorization: Bearer $T\"\nEOF\n"}, []string{"T"}, nil},
	{"safe: --only excludes the var", []string{`sh`, `-c`, `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://x`}, []string{"OTHER"}, nil},
	{"safe: echo builtin", []string{`sh`, `-c`, `echo "$T" | wc -c`}, []string{"T"}, nil},
	{"safe: export then program", []string{`sh`, `-c`, `export X="$T"; node app.js`}, []string{"T"}, nil},
	{"leak: mysql -p", []string{`sh`, `-c`, `mysql -p"$DB_PASSWORD" -h db`}, []string{"DB_PASSWORD"}, []string{"DB_PASSWORD"}},
	{"safe: here-string", []string{`sh`, `-c`, `jq -r .x <<< "$T"`}, []string{"T"}, nil},
	{"leak: double-quoted outer script with escaped $", []string{`sh`, `-c`, `curl -u "u:$T" https://x`}, []string{"T"}, []string{"T"}},
	{"safe: outer shell expands to the reference", []string{`curl`, `-H`, `Authorization: Bearer $T`, `https://x`}, []string{"T"}, nil},
	{"leak: zsh -ic", []string{`zsh`, `-ic`, `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com`}, []string{"GITHUB_TOKEN"}, []string{"GITHUB_TOKEN"}},
	{"leak: plain shell", []string{`sh`, `-c`, `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com`}, []string{"GITHUB_TOKEN"}, []string{"GITHUB_TOKEN"}},
	{"leak: env wrapper argv", []string{`sh`, `-c`, `env X="$T" prog`}, []string{"T"}, []string{"T"}},
	{"safe: assignment prefix is env", []string{`sh`, `-c`, `X="$T" prog --flag`}, []string{"T"}, nil},
	{"leak: printf -v copy", []string{`sh`, `-c`, `printf -v H "Bearer %s" "$T"; curl -H "Authorization: $H" x`}, []string{"T"}, []string{"T"}},
	{"leak: for loop variable", []string{`sh`, `-c`, `for t in "$T"; do curl -H "X: $t" x; done`}, []string{"T"}, []string{"T"}},
	{"leak: set -- then $1", []string{`sh`, `-c`, `set -- "$T"; curl -u "u:$1" x`}, []string{"T"}, []string{"T"}},
	{"leak: function argument", []string{`sh`, `-c`, `get() { curl -u "u:$1" "$2"; }; get "$T" https://x`}, []string{"T"}, []string{"T"}},
	{"safe: helper takes the token as $1, the URL as $2", []string{`sh`, `-c`, `get() { printf "header = \"Authorization: Bearer %s\"\n" "$1" | curl -sS -K - "$2"; }; get "$T" https://x`}, []string{"T"}, nil},
	{"leak: helper puts $1 in curl's arguments", []string{`sh`, `-c`, `get() { curl -sS -H "Authorization: Bearer $1" "$2"; }; get "$T" https://x`}, []string{"T"}, []string{"T"}},
	{"leak: shift moves $2 to $1", []string{`sh`, `-c`, `set -- url "$T"; shift; curl -u "u:$1" x`}, []string{"T"}, []string{"T"}},
	{"safe: set -- keeps positions apart", []string{`sh`, `-c`, `set -- "$T" url; printf %s "$1" | curl -K - "$2"`}, []string{"T"}, nil},
	{"leak: \"$@\" passes every parameter", []string{`sh`, `-c`, `f() { curl "$@"; }; f -u "u:$T" x`}, []string{"T"}, []string{"T"}},
	{"safe: function with printf to curl -K", []string{`sh`, `-c`, `g() { printf "header = \"Authorization: Bearer %s\"\n" "$T" | curl -sS -K - "$1"; }; g https://x`}, []string{"T"}, nil},
	{"safe: response of the safe form used later", []string{`sh`, `-c`, `R=$(printf "header = \"A: %s\"\n" "$T" | curl -sS -K - "$1"); python3 -c "import sys; print(sys.argv[1])" "$R"`, `_`, `https://x`}, []string{"T"}, nil},
	{"leak: local copy", []string{`bash`, `-c`, `f() { local h="Bearer $T"; curl -H "$h" x; }; f`}, []string{"T"}, []string{"T"}},
	{"leak: array", []string{`bash`, `-c`, `a=(-H "Authorization: Bearer $T"); curl "${a[@]}" x`}, []string{"T"}, []string{"T"}},
	{"safe: length only", []string{`sh`, `-c`, `curl -H "X-Len: ${#T}" x`}, []string{"T"}, nil},
	{"leak: partial value", []string{`sh`, `-c`, `curl -H "X: ${T:0:8}" x`}, []string{"T"}, []string{"T"}},
	{"safe: ${T:+word} is the word", []string{`sh`, `-c`, `curl ${T:+-K -} x`}, []string{"T"}, nil},
	{"leak: command wrapper", []string{`sh`, `-c`, `command curl -u "u:$T" x`}, []string{"T"}, []string{"T"}},
	{"safe: command printf is the builtin", []string{`sh`, `-c`, `command printf "%s" "$T" | curl -K - x`}, []string{"T"}, nil},
	{"leak: exec printf is a program", []string{`sh`, `-c`, `exec printf "%s" "$T"`}, []string{"T"}, []string{"T"}},
	{"leak: /bin/echo is a program", []string{`sh`, `-c`, `/bin/echo "$T"`}, []string{"T"}, []string{"T"}},
	{"leak: sudo", []string{`sh`, `-c`, `sudo -u me curl -u "u:$T" x`}, []string{"T"}, []string{"T"}},
	{"leak: nohup, timeout", []string{`sh`, `-c`, `nohup timeout 5 curl -H "X: $T" x`}, []string{"T"}, []string{"T"}},
	{"leak: xargs turns stdin into arguments", []string{`sh`, `-c`, `printf "%s\n" "$T" | xargs -I{} curl -H "X: {}" x`}, []string{"T"}, []string{"T"}},
	{"safe: env passes names, not values", []string{`sh`, `-c`, `env -u HOME prog`}, []string{"T"}, nil},
	{"leak: nested sh -c inherits the environment", []string{`sh`, `-c`, `bash -c 'curl -u "u:$T" x'`}, []string{"T"}, []string{"T"}},
	{"leak: nested sh -c positional", []string{`sh`, `-c`, `sh -c "curl -u u:\$1 x" _ "$T"`}, []string{"T"}, []string{"T"}},
	{"safe: nested sh -c without export", []string{`sh`, `-c`, `X="$T"; sh -c 'curl -H "$X" x'`}, []string{"T"}, nil},
	{"leak: nested sh -c with exported copy", []string{`sh`, `-c`, `export X="$T"; sh -c 'curl -H "$X" x'`}, []string{"T"}, []string{"T"}},
	{"leak: env wrapper runs sh -c", []string{`env`, `sh`, `-c`, `curl -u "u:$T" x`}, []string{"T"}, []string{"T"}},
	{"leak: eval of a value", []string{`sh`, `-c`, `eval "curl -u u:$T x"`}, []string{"T"}, []string{"T"}},
	{"leak: eval of literal text", []string{`sh`, `-c`, `eval 'curl -u "u:$T" x'`}, []string{"T"}, []string{"T"}},
	{"leak: read from a here-string", []string{`bash`, `-c`, `IFS=: read -r a b <<< "$T"; curl -u "$a:$b" x`}, []string{"T"}, []string{"T"}},
	{"leak: while read from a pipe", []string{`sh`, `-c`, `printf "%s\n" "$T" | while read -r t; do curl -H "X: $t" x; done`}, []string{"T"}, []string{"T"}},
	{"safe: substitution output to a file", []string{`sh`, `-c`, `R=$(printf "%s" "$T" > ./fake; echo ok); curl -H "X: $R" x`}, []string{"T"}, nil},
	{"leak: jq extracts from a here-string", []string{`bash`, `-c`, `tok=$(jq -r .t <<< "$T"); curl -H "X: $tok" x`}, []string{"T"}, []string{"T"}},
	{"safe: process substitution gives a path", []string{`bash`, `-c`, `curl -K <(printf "user = \"u:%s\"\n" "$T") x`}, []string{"T"}, nil},
	{"leak: printenv output", []string{`sh`, `-c`, `curl -H "X: $(printenv T)" x`}, []string{"T"}, []string{"T"}},
	{"leak: zsh print is a builtin, curl is not", []string{`zsh`, `-c`, `print -r -- $T | curl -K - x; curl -u u:$T[1,8] x`}, []string{"T"}, []string{"T"}},
	{"leak: tainted stdin becomes a script", []string{`sh`, `-c`, `printf "curl -u u:%s x" "$T" | sh`}, []string{"T"}, []string{"T"}},
	{"safe: docker login --password-stdin", []string{`sh`, `-c`, `printf %s "$T" | docker login -u me --password-stdin r.example`}, []string{"T"}, nil},
	{"leak: docker run -e NAME=value", []string{`sh`, `-c`, `docker run -e T="$T" img`}, []string{"T"}, []string{"T"}},
	{"safe: docker run -e NAME reads the environment", []string{`sh`, `-c`, `docker run -e T img`}, []string{"T"}, nil},
	{"leak: heredoc read by cat in a substitution", []string{`sh`, `-c`, "curl -u \"$(cat <<EOF\nu:$T\nEOF\n)\" x"}, []string{"T"}, []string{"T"}},
	{"leak: \"$@\" as the command", []string{`sh`, `-c`, `f() { "$@"; }; f curl -u "u:$T" x`}, []string{"T"}, []string{"T"}},
	{"leak: program named by a variable", []string{`sh`, `-c`, `c=curl; $c -u "u:$T" x`}, []string{"T"}, []string{"T"}},
	{"leak: select variable", []string{`bash`, `-c`, `select x in "$T"; do curl -H "$x" x; break; done`}, []string{"T"}, []string{"T"}},
	{"leak: substitution inside [[ ]]", []string{`bash`, `-c`, `[[ $(curl -u "u:$T" x) == ok ]]`}, []string{"T"}, []string{"T"}},
	{"leak: exec redirection from a process substitution", []string{`bash`, `-c`, `exec 3< <(curl -u "u:$T" x)`}, []string{"T"}, []string{"T"}},
	{"leak: read from a heredoc", []string{`sh`, `-c`, "read -r H <<EOF\nAuthorization: Bearer $T\nEOF\ncurl -H \"$H\" x"}, []string{"T"}, []string{"T"}},
	{"leak: mapfile from a here-string", []string{`bash`, `-c`, `mapfile -t l <<< "$T"; curl -H "${l[0]}" x`}, []string{"T"}, []string{"T"}},
	{"leak: local -x exports to a child shell", []string{`bash`, `-c`, `f() { local -x X="$T"; sh -c 'curl -H "$X" x'; }; f`}, []string{"T"}, []string{"T"}},
	{"leak: trap runs its text as code", []string{`sh`, `-c`, `trap 'curl -u "u:$T" x' EXIT`}, []string{"T"}, []string{"T"}},
	{"safe: trap with a reset", []string{`sh`, `-c`, `trap - EXIT; printf %s "$T" | curl -K - x`}, []string{"T"}, nil},
}

func TestCheckFindsEachVariableOfACommandLine(t *testing.T) {
	for _, tc := range commandLines {
		var got []string
		if sh, script, ok := shell.Command(tc.argv); ok {
			found, err := shell.Check(sh, script, tc.resolved)
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			for _, f := range found {
				got = append(got, f.Var)
			}
			slices.Sort(got)
			got = slices.Compact(got)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: found %v, want %v", tc.name, got, tc.want)
		}
	}
}

// brief writes findings without their advice, for messages and comparisons.
func brief(found []shell.Finding) string {
	var out []string
	for _, f := range found {
		in := " in "
		if f.Code {
			in = " as code in "
		}
		out = append(out, f.Var+in+f.Program+" at line "+strconv.Itoa(f.Line))
	}
	return strings.Join(out, "; ")
}

// A finding names the variable whose value would be in a command line, under
// its own name even when a copy carries it, the program whose command line it
// is, and the line that would put it there. A value that eval, trap, alias or
// a shell reading stdin would run as code is in no command line of theirs.
func TestCheckNamesTheVariableProgramAndLine(t *testing.T) {
	for _, tc := range []struct {
		what, shell, script string
		resolved            []string
		want                string
	}{
		{"a copy", "sh", "H=\"Bearer $T\"\ncurl -H \"Authorization: $H\" x", onlyT, "T in curl at line 2"},
		{"both of a user and password", "sh", `curl -u "$JIRA_API_EMAIL:$JIRA_API_TOKEN" x`, jira,
			"JIRA_API_EMAIL in curl at line 1; JIRA_API_TOKEN in curl at line 1"},
		{"a word on a joined line", "sh", "curl -s \\\n  -H 'Accept: x' \\\n  -u \"u:$T\" \\\n  https://x", onlyT, "T in curl at line 3"},
		{"env's own word", "sh", `env API_TOKEN="$T" node app.js`, onlyT, "T in env at line 1"},
		{"env's own word, of a name no shell assigns", "sh", `env A.B="$T" node app.js`, onlyT, "T in env at line 1"},
		{"a program that launchers run", "sh", `nohup timeout 5 curl -u "u:$T" x`, onlyT, "T in curl at line 1"},
		{"what xargs reads", "sh", `printf '%s' "$T" | xargs -I{} curl -H "X: {}" x`, onlyT, "T in curl at line 1"},
		{"a word of a shell's command line", "sh", `sh -c 'printf "%s" "$1" | curl -K - x' _ "$T"`, onlyT, "T in sh at line 1"},
		{"a shell's script", "sh", "sh -c '\ncurl -u \"u:$T\" x'", onlyT, "T in curl at line 2"},
		{"a shell's script on stdin", "sh", "sh <<'EOF'\n\ncurl -u \"u:$T\" x\nEOF", onlyT, "T in curl at line 3"},
		{"sh -s's script on stdin", "sh", "sh -s a <<'EOF'\ncurl -u \"u:$T\" x\nEOF", onlyT, "T in curl at line 2"},
		{"bash's script in a here-string", "sh", `bash <<<'curl -u "u:$T" x'`, onlyT, "T in curl at line 1"},
		{"a value a shell would run as code", "sh", "sh <<EOF\ncurl -u \"u:$T\" x\nEOF", onlyT, "T as code in sh at line 1"},
		{"a value piped to a shell", "sh", `printf 'curl -u u:%s x' "$T" | sh`, onlyT, "T as code in sh at line 1"},
		{"a value a shell gets as a word and as code", "sh", `printf '%s' "$T" | sh -s "$T"`, onlyT, "T in sh at line 1; T as code in sh at line 1"},
		{"a function's body", "sh", "f() {\n  curl -u \"u:$1\" x\n}\nf \"$T\"", onlyT, "T in curl at line 2"},
		{"eval's code", "sh", `eval "curl -u u:$T x"`, onlyT, "T as code in eval at line 1"},
		{"trap's command", "sh", `trap "curl -u u:$T x" EXIT`, onlyT, "T as code in trap at line 1"},
		{"an alias's text", "sh", "alias jc='curl -u \"u:$T\"'\njc x", onlyT, "T in curl at line 2"},
		{"code a variable is given, where it is written", "sh", "cmd='curl -u \"u:$T\" x'\neval \"$cmd\"", onlyT, "T in curl at line 1"},
		{"an alias given the value", "sh", `alias jc="curl -u u:$T"`, onlyT, "T as code in alias at line 1"},
		{"exec -a", "bash", `exec -a "$T" sleep 1`, onlyT, "T in sleep at line 1"},
		{"a path", "sh", `/usr/bin/printf '%s' "$T"`, onlyT, "T in printf at line 1"},
		{"a program named by a variable", "sh", `c=curl; $c -u "u:$T" x`, onlyT, "T in $c at line 1"},
		{"a name that could hide a value", "sh", `"curl -u u:pw" -u "u:$T" x`, onlyT, "T in a program at line 1"},
		{"a name with digits among capitals, as a key has", "sh", `/opt/bin/` + written + ` "$T"`, onlyT, "T in a program at line 1"},
		{"a name longer than a program's", "sh", `xargs abcdefghijklmnopqrstuvwxy "$T"`, onlyT, "T in a program at line 1"},
		{"a program's long name", "sh", `github-mcp-server --token "$T"`, onlyT, "T in github-mcp-server at line 1"},
		{"a copy made in a later pass of a loop", "sh", `for i in 1 2; do curl -H "$h" x; h="X: $T"; done`, onlyT, "T in curl at line 1"},
		{"copies made over three passes", "sh", `for i in 1 2 3; do curl -H "$c" x; c=$b; b=$T; done`, onlyT, "T in curl at line 1"},
		{"two commands on one line", "sh", `curl -u "u:$T" a; curl -H "X: $T" b`, onlyT, "T in curl at line 1; T in curl at line 1"},
		{"lines in order", "sh", "f() { curl -u \"u:$1\" x; }\ncurl -H \"X: $T\" y\nf \"$T\"", onlyT, "T in curl at line 1; T in curl at line 2"},
	} {
		found, err := shell.Check(tc.shell, tc.script, tc.resolved)
		if got := brief(found); err != nil || got != tc.want {
			t.Errorf("%s: found %q, %v; want %q", tc.what, got, err, tc.want)
		}
	}
}

// These are scripts an MCP server's keyward run is given: those that mcp
// wrap has written, in one version or another, and some written by hand.
func TestCheckJudgesTheScriptsMCPWrapWrites(t *testing.T) {
	for _, tc := range []struct {
		what, script string
		resolved     []string
		refuse       bool
	}{
		{"a bridge since 1.2.0, which leaves ${VAR} for mcp-remote", `exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer "'$''{GITHUB_TOKEN}'"" --transport http-only`, []string{"GITHUB_TOKEN"}, allow},
		{"an SSE bridge", `exec npx -y mcp-remote https://api.example.com/sse --header "Authorization: Bearer "'$''{GITHUB_TOKEN}'"" --transport sse-only`, []string{"GITHUB_TOKEN"}, allow},
		{"a header moved to env", `exec npx -y mcp-remote https://mcp.example.com/mcp --header "X-Team: "'$''{KW_HDR_1}'"" --transport http-only`, []string{"KW_HDR_1"}, allow},
		{"a server's own script, rewritten in place", `cd / && exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header 'Authorization: Bearer $''{JIRA}'`, []string{"JIRA"}, allow},
		{"a token in the server's environment", `GITHUB_PERSONAL_ACCESS_TOKEN="$GITHUB_TOKEN" exec github-mcp-server stdio`, []string{"GITHUB_TOKEN"}, allow},
		{"a key on stdin", `printf '%s' "$PD_KEY" | exec some-mcp --key-stdin`, []string{"PD_KEY"}, allow},
		{"a script naming no resolved variable", `exec some-mcp --token "$(cat ~/.token)"`, []string{"GITHUB_TOKEN"}, allow},
		{"a key in the URL, wrapped with --allow-command-line", `exec npx -y mcp-remote "https://mcp.example.com/mcp?key=$PD_KEY" --transport http-only`, []string{"PD_KEY"}, refuse},
		{"a token as an argument", `exec npx -y slack-mcp --token "$GITHUB_TOKEN"`, []string{"GITHUB_TOKEN"}, refuse},
		{"an option holding a key", `exec tool "--api-key=$PD_KEY"`, []string{"PD_KEY"}, refuse},
		{"exec printf, the program", `exec printf "[%s]" --token "$GH_TOKEN"`, []string{"GH_TOKEN"}, refuse},
		{"a bridge before 1.1.4", `exec npx -y mcp-remote https://api.example.com/mcp/ --header "Authorization: Bearer $GITHUB_TOKEN" --transport http-only`, []string{"GITHUB_TOKEN"}, refuse},
		{"a stdio bridge of 1.1.4 to 1.1.7", `exec npx -y mcp-remote https://mcp.example.com/v1/mcp --header "Authorization: Bearer $JIRA"`, []string{"JIRA"}, refuse},
		{"a nested script passing a token", `exec sh -c "exec some-mcp --token \"$GITHUB_TOKEN\""`, []string{"GITHUB_TOKEN"}, refuse},
		{"a nested script setting a token", `exec sh -c "GITHUB_PERSONAL_ACCESS_TOKEN=$GITHUB_TOKEN exec github-mcp-server stdio"`, []string{"GITHUB_TOKEN"}, refuse},
		{"a nested script piping a key", `exec bash -c "printf '%s' \"$PD_KEY\" | exec some-mcp --key-stdin"`, []string{"PD_KEY"}, refuse},
		{"a hand-written bridge", `npx -y mcp-remote https://mcp.example.com/mcp --header "Authorization: Bearer $T"`, onlyT, refuse},
	} {
		found, err := shell.Check("sh", tc.script, tc.resolved)
		if got := len(found) > 0; err != nil || got != tc.refuse {
			t.Errorf("%s: refused = %v, %v; want %v; found %s", tc.what, got, err, tc.refuse, brief(found))
		}
	}
}

// A script that cannot be read, or followed to its end, may do anything with
// a value it names, but one that names none has none to leak.
func TestCheckRefusesAScriptItCannotReadOnlyIfItNamesAValue(t *testing.T) {
	for _, tc := range []struct {
		what, shell, script string
		unreadable          bool
	}{
		{"zsh's short for loop", "zsh", `for x (a b) curl -u "u:$T" x`, true},
		{"the value named in braces", "zsh", `for x (a b) curl -u "u:${T}" x`, true},
		{"no value named", "zsh", `for x (a b) print $x`, false},
		{"another variable", "zsh", `for x (a b) print $Tx`, false},
		{"a nested script", "sh", `sh -c 'for x (a b) curl -u "u:$T" x'`, true},
		{"a nested script naming no value", "sh", `sh -c 'for x (a b) echo $x'`, false},
		{"scripts too deeply nested", "sh", nestedScripts(20), true},
		{"functions that would take hours to follow", "sh", fanOut(60, `curl -u "u:$T" x`), true},
		{"the same naming no value", "sh", fanOut(60, `curl x`), false},
		{"a script nested deeper than the parser's stack allows", "sh", tooDeep + `curl -u "u:$T" x`, true},
		{"the same naming no value", "sh", tooDeep + `curl x`, false},
		{"a loop that passes a value along more variables than the check reads passes", "sh", loopChain(9, "$T"), true},
		{"the same naming only copies of a value", "sh", loopChain(9, "$(printenv T)"), true},
		{"a function that passes a value along more variables than the check reads calls", "sh", callChain(20, "$T"), true},
		{"a copy printenv makes after functions that would take hours", "sh", fanOut(60, ":") + `X=$(printenv T); curl -u "u:$X" x`, true},
		{"the value read by its name after them", "bash", fanOut(60, ":") + `n=T; curl -u "u:${!n}" x`, true},
		{"a copy made in a subshell before them", "sh", "( X=$(printenv T)\n" + fanOut(60, ":") + `curl -u "u:$X" x )`, true},
		{"every value, which env prints, copied before them", "sh", "X=$(env)\n" + fanOut(60, ":") + `curl -u "u:$X" x`, true},
		{"a loop in a subshell that passes a copy along too many variables", "sh", "( " + loopChain(9, "$(printenv T)") + " )", true},
		{"the same in a substitution", "sh", "v=$(" + loopChain(9, "$(printenv T)") + ")", true},
		{"a script that names the value only as a word", "zsh", `for x (a b) print $x; X=$(printenv T); curl -u "u:$X" x`, true},
		{"a word that holds the name in a longer one", "zsh", `for x (a b) print $x; printenv TX`, false},
		{"code made as the script runs, which literal text naming the value could be", "sh", `eval "$(curl -s https://x.example.com/setup)"; jq -r '.items[] | "\(.name) $T"' ./items.json`, true},
		{"code made as the script runs, with no literal text naming a value", "sh", `eval "$(curl -s https://x.example.com/setup)"; printf '%s' "$T" | curl -K - x`, false},
		{"code a variable reads", "sh", `read -r cmd < ./cmd.txt; eval "$cmd"; c='curl -u "u:$T" x'`, true},
		{"code a function is given", "sh", `f() { eval "$1"; }; f 'curl -u "u:$T" x'`, true},
		{"code a shell inherits", "sh", `export cmd='curl -u "u:$T" x'; sh -c 'eval "$cmd"'`, true},
		{"code a command named as the script runs may run, as eval does", "sh", `e=eval; $e 'curl -u "u:$T" x'`, true},
		{"the same of a variable's code", "dash", `e=eval; c='curl -u "u:$T" x'; $e "$c"`, true},
		{"the same of code that names the value as a word", "bash", `e=eval; $e 'X=$(printenv T); curl -u "u:$X" x'`, true},
		{"code a function's \"$@\" may run, as sh -c does", "zsh", `run() { "$@"; }; run sh -c 'curl -u "u:$T" x'`, true},
		{"words of a command named as the script runs that name no value", "sh", `cmd=curl; $cmd -s x; printf '%s' "$T" | curl -K - x`, false},
		{"code that grows past what the check keeps of it", "sh", `c=""; for i in 1 2 3 4 5 6; do c="$c -v"; done; eval "curl $c x"`, false},
		{"a \"$@\" the check cannot know, run at every call of functions that would take hours, among many short literals", "sh", fanArgs(30, `command "$@"`) + strings.Repeat(": $\n", 15000), false},
		{"variables that each hold the one before twice", "sh", doubling(24, `printf %s "$T" | wc -c`), true},
		{"the same naming no value", "sh", doubling(24, "wc -c </dev/null"), false},
	} {
		found, err := shell.Check(tc.shell, tc.script, onlyT)
		if (err != nil) != tc.unreadable || len(found) > 0 {
			t.Errorf("%s: found %s, error %v; want unreadable %v", tc.what, brief(found), err, tc.unreadable)
		}
	}
	if found, err := shell.Check("sh", nestedScripts(3), onlyT); err != nil || brief(found) != "T in curl at line 4" {
		t.Errorf("three scripts deep: found %s, %v", brief(found), err)
	}
	// What the check found before it stopped is still found.
	if found, err := shell.Check("sh", "curl -H \"X: $(printenv)\" x\n"+fanOut(60, `curl x`), onlyT); err != nil || brief(found) != "T in curl at line 1" {
		t.Errorf("a finding before functions that would take hours: found %s, %v", brief(found), err)
	}
}

// A long script that sets many variables is cheap to check, however many
// variables the shells know, as each line costs the check the same.
func TestCheckFollowsALongScriptOfManyVariablesToItsEnd(t *testing.T) {
	// lines writes n lines of format, each with its number for %[1]d.
	lines := func(n int, format string) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, format+"\n", i)
		}
		return b.String()
	}
	const safe = `printf 'user = "u:%s"\n' "$T" | curl -K - https://x.example.com`
	var fields []string
	for i := range 20 {
		fields = append(fields, fmt.Sprintf(`\"k%d\":\"$F%d\"`, i, i))
	}
	for what, script := range map[string]string{
		"700 variables that set -a exports, each piped to a program": "set -a\n" + lines(700, "K%[1]d=value%[1]d") +
			lines(700, `echo "$K%[1]d" | tr a-z A-Z`) + safe,
		"the same, each in a substitution": "set -a\n" + lines(700, "K%[1]d=value%[1]d") +
			lines(700, `U%[1]d=$(echo "$K%[1]d" | tr a-z A-Z)`) + safe,
		"900 exports, each tested": lines(900, `export V%[1]d=v%[1]d; [ -n "$V%[1]d" ] && echo ok`) + safe,
		"400 copies of the value exported, each sent on stdin": lines(400, `export E%[1]d="$T"`) +
			lines(400, `printf 'user = "u:%%s"\n' "$E%[1]d" | curl -s -K - https://x.example.com/%[1]d`),
		// The text a variable keeps for eval counts once, however often it is
		// assigned again.
		"a function that writes a body of 20 fields the script set, called 100 times": lines(20, "F%[1]d=value-%[1]d-"+strings.Repeat("v", 24)) +
			`post() { body="{` + strings.Join(fields, ",") + `}"; printf '%s' "$body" | curl -s --data-binary @- https://x.example.com; }` + "\n" +
			strings.Repeat("post\n", 100) + safe,
		"a body of 10 KB written into a function called 200 times": "post() { body='" + strings.Repeat("v", 10<<10) +
			`'; printf '%s' "$body" | curl -s --data-binary @- https://x.example.com; }` + "\n" + strings.Repeat("post\n", 200) + safe,
	} {
		if found, err := shell.Check("sh", script, onlyT); err != nil || len(found) > 0 {
			t.Errorf("%s (%d KB): found %s, %v", what, len(script)>>10, brief(found), err)
		}
	}
}

// tooDeep nests 2^18 parentheses, which the parser would recurse into until
// it ran out of stack.
var tooDeep = "x=$((" + strings.Repeat("(", 1<<18) + "1" + strings.Repeat(")", 1<<18) + "))\n"

// fanOut returns a script whose functions each call the next twice, n deep,
// so that the last, which runs leaf, would run 2^(n-1) times.
func fanOut(n int, leaf string) string {
	var b strings.Builder
	for i := 1; i < n; i++ {
		b.WriteString("f" + strconv.Itoa(i) + "() { f" + strconv.Itoa(i+1) + "; f" + strconv.Itoa(i+1) + "; }\n")
	}
	b.WriteString("f" + strconv.Itoa(n) + "() { " + leaf + "; }\nf1\n")
	return b.String()
}

// A "$@" the check cannot know may run any literal text, so the check scans
// every literal at each call; uncounted, 30,000 short ones made it 40 times slower.
func TestCheckCountsEveryTextItScansForCodeAsWork(t *testing.T) {
	check := func(lines int) time.Duration {
		start := time.Now()
		if _, err := shell.Check("sh", fanArgs(30, `command "$@"`)+strings.Repeat(": $\n", lines)+`curl -u "u:$T" x`, onlyT); err == nil {
			t.Fatal("a script the check gave up on, which names the value, ran")
		}
		return time.Since(start)
	}
	// However fast the machine, the literals cost no more than the calls already do.
	calls := check(0)
	if literals := check(15000); literals > 3*calls || literals > time.Minute {
		t.Errorf("checking 30,000 short literals took %v, against %v without them", literals, calls)
	}
}

// fanArgs is fanOut with each call passing its arguments on, so the leaf's
// "$@" holds the script's own arguments, which the check cannot know.
func fanArgs(n int, leaf string) string {
	var b strings.Builder
	for i := 1; i < n; i++ {
		b.WriteString("f" + strconv.Itoa(i) + "() { f" + strconv.Itoa(i+1) + ` "$@"; f` + strconv.Itoa(i+1) + ` "$@"; }` + "\n")
	}
	b.WriteString("f" + strconv.Itoa(n) + "() { " + leaf + "; }\nf1 \"$@\"\n")
	return b.String()
}

// loopChain returns a loop that passes value along n variables, a variable a
// pass, then puts the last in curl's command line, as it does on every shell.
func loopChain(n int, value string) string {
	var b strings.Builder
	b.WriteString(`i=0; while [ "$i" -lt 20 ]; do `)
	for j := n; j > 0; j-- {
		b.WriteString("a" + strconv.Itoa(j) + "=$a" + strconv.Itoa(j-1) + "; ")
	}
	b.WriteString("a0=" + value + `; i=$((i+1)); done; curl -H "X-Key: $a` + strconv.Itoa(n) + `" https://x.example.com`)
	return b.String()
}

// callChain returns a function that passes value along n variables, a
// variable a call, then calls itself, until the last reaches curl's command
// line, as it does on every shell.
func callChain(n int, value string) string {
	var b strings.Builder
	last := "$a" + strconv.Itoa(n)
	b.WriteString(`f() { curl -H "X-Key: ` + last + `" https://x.example.com; [ -n "` + last + `" ] && return; `)
	for j := n; j > 0; j-- {
		b.WriteString("a" + strconv.Itoa(j) + "=$a" + strconv.Itoa(j-1) + "; ")
	}
	b.WriteString("a0=" + value + "; f; }; f")
	return b.String()
}

// doubling returns a script whose variables each hold the one before twice,
// n deep, as a1="$a0$a0" does, then runs last.
func doubling(n int, last string) string {
	var b strings.Builder
	b.WriteString("a0=xxxxxxxx\n")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "a%d=\"$a%d$a%d\"\n", i, i-1, i-1)
	}
	return b.String() + last
}

// A script of a few hundred bytes whose variables double what they hold
// would have the check keep gigabytes of the text eval could run.
func TestCheckKeepsLittleOfTheTextVariablesHold(t *testing.T) {
	script := doubling(24, `printf %s "$T" | wc -c`)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	shell.Check("sh", script, onlyT)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Errorf("checking a script of %d bytes allocated %d MB", len(script), allocated>>20)
	}
}

// exec > >(...) sends the output of every later command there too, so a
// script that opens a thousand of them, or has eval open one again on each
// call, made every later command cost the check their number squared, and a
// script of 16 KB took minutes.
func TestCheckFollowsWhatExecOpensForEveryLaterCommandInMoments(t *testing.T) {
	const leak = `curl -u "u:$T" x`
	for _, tc := range []struct {
		what, shell, script string
		unreadable          bool
	}{
		{"one that eval opens again on every call", "bash", "x='exec > >(:)'\nf() { eval \"$x\"; }\n" + strings.Repeat("f\n", 4000) + leak, false},
		{"a thousand, then thousands of commands", "bash", strings.Repeat("exec > >(:)\n", 1000) + strings.Repeat(":\n", 4000) + leak, true},
		{"the same in a function called again and again", "bash", "f() {\n" + strings.Repeat("exec > >(:)\n", 1000) + strings.Repeat(":\n", 2000) + "}\n" + strings.Repeat("f\n", 100) + leak, true},
		{"a thousand on one command in zsh, which writes to each", "zsh", "exec" + strings.Repeat(" > >(:)", 1000) + "\n" + strings.Repeat(":\n", 4000) + leak, true},
	} {
		start := time.Now()
		found, err := shell.Check(tc.shell, tc.script, onlyT)
		if took := time.Since(start); took > time.Second {
			t.Errorf("%s: took %v", tc.what, took)
		}
		if (err != nil) != tc.unreadable || err == nil && len(found) == 0 {
			t.Errorf("%s: found %s, error %v; want unreadable %v, or the value in curl's command line", tc.what, brief(found), err, tc.unreadable)
		}
	}
}

// nestedScripts returns a script that runs a script, n shells deep, through
// here-documents; the innermost puts $T in curl's command line.
func nestedScripts(n int) string {
	script := `curl -u "u:$T" x`
	for i := n; i > 0; i-- {
		delimiter := "E" + strconv.Itoa(i)
		script = "sh <<'" + delimiter + "'\n" + script + "\n" + delimiter
	}
	return script
}

// The parser quotes some words of a script in its messages, and one could be a
// credential written into the script, in backquotes or, if it holds a backquote
// or a control character, in double quotes. Only the shell's grammar is shown.
func TestCheckSaysWhyItCannotReadAScriptWithoutItsWords(t *testing.T) {
	for _, tc := range []struct{ shell, script, want string }{
		{"bash", "echo ok\n[[ $T " + written + " b ]]", "line 2: not a valid test operator: `...`"},
		{"bash", `[[ $T hunterpass b ]]`, "line 1: not a valid test operator: `...`"},
		{"bash", `[[ "$T" -` + written + "\x01 x ]]", "line 1: not a valid test operator: `...`"},
		{"bash", `echo $(( $T hunterpass 2 ))`, "line 1: not a valid arithmetic operator: `...`"},
		{"bash", `echo ${T@hunterpass}`, "line 1: invalid @ expansion operator `...`"},
		{"bash", "cat <<hunterpass\n$T", "line 1: unclosed here-document `...`"},
		{"zsh", "curl -u \"u:$T\" x; cat <<'X`" + written + "'", "line 1: unclosed here-document `...`"},
		{"sh", "cat <<'" + written + "\nx'\n$T", "line 1: unclosed here-document `...`"},
		{"zsh", `for x (a b) curl -u "u:$T" x`, "line 1: `for foo` must be followed by `in`, `do`, `;`, or a newline"},
		{"sh", `for x in a; curl -u "u:$T" x; done`, "line 1: `for foo [in words]` must be followed by `do`"},
		{"sh", "curl -u \"u:$T\" `x", "line 1: reached EOF without closing quote \"`\""},
		{"bash", `[[ -n $T && ]]`, "line 1: `&&` must be followed by an expression"},
		{"sh", "curl -u \"u:$T\" x\necho ${(P)name}", "line 2: parameter expansion flags are a zsh feature; tried parsing as bash"},
		{"sh", fanOut(60, `curl -u "u:$T" x`), "the script would take too long to check"},
		{"sh", tooDeep + `curl -u "u:$T" x`, "scripts over 64 KB are too long to check"},
		{"sh", callChain(20, "$T"), "a function calls itself too deeply to check"},
		{"sh", doubling(24, `printf %s "$T" | wc -c`), "the script's variables would hold too much text to check"},
		{"sh", "f() { eval \"$1\"; }\nf 'curl -u \"u:$T\" x'", "line 1: eval runs code made as the script runs"},
		{"sh", "e=eval\n$e 'curl -u \"u:$T\" x'", "line 2: a command named as the script runs may run its words as code"},
	} {
		if _, err := shell.Check(tc.shell, tc.script, onlyT); err == nil || err.Error() != tc.want {
			t.Errorf("error = %v, want %s", err, tc.want)
		}
	}
}

// What would let the check read a script depends on why it cannot: sh syntax
// for zsh's, which the parser reads only in part, or another shell's; a fixed
// syntax error, as in an sh script; a space in a $(( or (( that starts a
// subshell, which bash and zsh run; a simpler script for one too much to
// follow; and code written into the script, not made as it runs.
func TestCheckSaysHowToWriteAScriptItCannotRead(t *testing.T) {
	const (
		inSh     = "Write it in sh syntax for sh -c, which keyward run can read."
		fix      = "Fix its syntax, so keyward run can read it."
		space    = "keyward run reads $(( and (( as arithmetic: write $( ( and ( ( to start a subshell inside, or fix the arithmetic."
		simpler  = "Write it more simply, so keyward run can check it."
		writeOut = "Write that code into the script, or leave it out, so keyward run can read what runs."
		name     = "Write the command's name into the script, so keyward run can read what it runs."
	)
	for _, tc := range []struct{ what, shell, script, want string }{
		{"zsh's syntax", "zsh", `for x (a b) curl -u "u:$T" x`, inSh},
		{"a zsh script inside an sh script", "sh", `zsh -c 'for x (a b) curl -u "u:$T" x'`, inSh},
		{"zsh's syntax in an sh script", "sh", `echo ${(P)name} "$T"`, inSh},
		{"an sh script's syntax error", "sh", `if [ -n "$T" ]; then curl -u "u:$T" x`, fix},
		{"a bash script's", "bash", `[[ -n $T && ]]`, fix},
		{"an sh script inside a zsh script", "zsh", `sh -c 'if [ -n "$T" ]; then curl -u "u:$T" x'`, fix},
		{"$(( that starts a subshell", "bash", `x=$((curl -s -u "u:$T" x) | jq .)`, space},
		{"(( that starts one", "sh", `((curl -u "u:$T" x) | jq .)`, space},
		{"an arithmetic error", "bash", `echo $(( $T hunterpass 2 ))`, space},
		{"scripts too deeply nested", "sh", nestedScripts(20), simpler},
		{"a script too long", "sh", tooDeep + `curl -u "u:$T" x`, simpler},
		{"functions that would take hours", "sh", fanOut(60, `curl -u "u:$T" x`), simpler},
		{"a loop that passes a value along too many variables", "sh", loopChain(9, "$T"), simpler},
		{"a function that calls itself too deeply", "sh", callChain(20, "$T"), simpler},
		{"variables that hold too much text", "sh", doubling(24, `printf %s "$T" | wc -c`), simpler},
		{"code made as the script runs", "sh", `f() { eval "$1"; }; f 'curl -u "u:$T" x'`, writeOut},
		{"a command named as the script runs", "sh", `e=eval; $e 'curl -u "u:$T" x'`, name},
	} {
		_, err := shell.Check(tc.shell, tc.script, onlyT)
		if got := shell.Hint(err); err == nil || got != tc.want {
			t.Errorf("%s: %v, hint %q; want %q", tc.what, err, got, tc.want)
		}
	}
}

// Each script follows one rule of the shell that the check must know.
func TestCheckFollowsTheShellsRules(t *testing.T) {
	for _, tc := range []struct {
		what, shell, script string
		refuse              bool
	}{
		// Copies.
		{"read -u from a descriptor exec opened", "bash", `exec 3<<<"$T"; read -r -u 3 v; curl -u "u:$v" x`, refuse},
		{"read -a", "bash", `read -ra parts <<< "$T"; curl -H "X: ${parts[0]}" x`, refuse},
		{"read after --", "bash", `read -r -- v <<< "$T"; curl -u "u:$v" x`, refuse},
		{"read -u with its descriptor attached", "bash", `exec 3<<<"$T"; read -ru3 v; curl -u "u:$v" x`, refuse},
		{"read with no name, which sets REPLY", "bash", `read <<< "$T"; curl -u "u:$REPLY" x`, refuse},
		{"mapfile with no name, which sets MAPFILE", "bash", `mapfile <<< "$T"; curl -H "${MAPFILE[0]}" x`, refuse},
		{"mapfile from a descriptor", "bash", `mapfile -u 3 lines 3<<<"$T"; curl -H "${lines[0]}" x`, refuse},
		{"a here-document on fd 0 that exec keeps", "sh", "exec <<EOF\n$T\nEOF\nread -r v; curl -u \"u:$v\" x", refuse},
		{"input from a process substitution", "bash", `read -r v < <(printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"an arithmetic assignment", "bash", `(( n = PIN * 1 )); curl "https://x.example.com/?pin=$n"`, refuse},
		{"let", "bash", `let "n = PIN"; curl "https://x.example.com/?pin=$n"`, refuse},
		{"arithmetic in parentheses, with a sign", "sh", `curl "https://x.example.com/?pin=$(( (PIN) + -1 ))"`, refuse},
		{"a replacement in the value", "bash", `curl "https://x.example.com/?k=${T/a/b}"`, refuse},
		{"${K:=word}, which assigns the word", "sh", `: "${K:=$T}"; curl -H "X-Key: $K" x`, refuse},
		{"${K=word}, which assigns it if K is unset", "dash", `: "${K=$T}"; curl -H "X-Key: $K" x`, refuse},
		{"an assigning expansion inside another word", "sh", `echo "using ${API_KEY:=$T}" >/dev/null; curl -H "X-Key: $API_KEY" x`, refuse},
		{"an assigning expansion of no value", "sh", `: "${URL:=https://x.example.com}"; printf '%s' "$T" | curl -K - "$URL"`, allow},
		{"=~, which copies what it matches into BASH_REMATCH", "bash", `[[ $T =~ ^(.*)$ ]] && curl -H "X: ${BASH_REMATCH[1]}" x`, refuse},
		{"zsh's =~, which copies it into MATCH", "zsh", `[[ $T =~ '^.*$' ]] && curl -H "X: $MATCH" x`, refuse},
		{"zsh's =~, which copies it into match", "zsh", `[[ $T =~ '^(.*)$' ]] && curl -H "X: $match[1]" x`, refuse},
		{"=~ of other text against the value", "bash", `[[ abc =~ $T ]] && curl -H "X: ${BASH_REMATCH[0]}" x`, allow},
		{"zsh's $argv, the positional parameters", "zsh", `f() { curl -u "u:$argv[1]" x; }; f "$T"`, refuse},
		{"zsh's read -A with no name, which sets reply", "zsh", `read -A <<< "$T"; curl -u "u:$reply" x`, refuse},
		{"$_, the last word of the command before", "sh", `: "$T"; curl -H "X: $_" x`, refuse},
		{"$_ in dash, which sets none", "dash", `: "$T"; curl -H "X: $_" x`, allow},
		{"$_ after an assignment, which sets none", "zsh", `X=$T; curl -H "X: $_" x`, allow},
		{"zsh's nested expansion", "zsh", `curl -u "u:${${T}}" x`, refuse},
		{"zsh's print -v", "zsh", `print -v h "Bearer $T"; curl -H "Authorization: $h" x`, refuse},
		{"getopts reading a function's parameters", "sh", `f() { getopts t: o; curl -u "u:$OPTARG" x; }; f -t "$T"`, refuse},
		{"shift by a count", "sh", `set -- a "$T"; shift 1; curl -u "u:$1" x`, refuse},
		{"shift by a count it cannot know", "sh", `set -- a "$T"; shift "$n"; curl -u "u:$1" x`, refuse},
		{"shift past every parameter, which shifts nothing", "sh", `set -- "$T"; shift 5; curl -u "u:$1" x`, refuse},
		{"a negative shift, which the shell refuses", "sh", `set -- a "$T"; shift -2; curl -u "u:$2" x`, refuse},
		{"a function's negative shift", "sh", `f() { shift -3; curl -u "u:$1" x; }; f "$T"`, refuse},
		{"a shift by the largest count an int holds", "sh", `set -- a "$T"; shift 9223372036854775807; curl -u "u:$2" x`, refuse},
		{"a shift by more than an int holds", "sh", `set -- a "$T"; shift 10000000000000000000; curl -u "u:$2" x`, refuse},
		{"set with operands", "sh", `set a "$T"; curl -u "u:$2" x`, refuse},
		{"\"${a[@]}\", which may be any number of words", "bash", `a=(x y); f() { curl -s "$3"; }; f "${a[@]}" "$T"`, refuse},
		{"a glob, which may expand to any number of words", "sh", `f() { curl -s "$3"; }; f *.txt "$T" https://x.example.com`, refuse},
		{"a nameref to a variable it cannot know", "bash", `declare -n r="$1"; curl -u "u:$r" x`, refuse},
		{"set -o allexport", "sh", `set -o allexport; X=$T; sh -c 'curl -u "u:$X" x'`, refuse},
		{"set -o pipefail, which exports nothing", "sh", `set -eo pipefail; X=$T; sh -c 'curl -u "u:$X" x'`, allow},
		{"zsh's setopt allexport", "zsh", `setopt ALL_EXPORT; X=$T; sh -c 'curl -u "u:$X" x'`, refuse},
		{"a prefix assignment to a special builtin outlasts it", "sh", `X="$T" :; curl -u "u:$X" x`, refuse},
		{"a function's prefix assignment, in its commands' environment", "sh", `f() { sh -c 'curl -u "u:$X" x'; }; X="$T" f`, refuse},
		{"export through command", "sh", `command export X="$T"; sh -c 'curl -u "u:$X" x'`, refuse},
		{"export of a quoted assignment", "sh", `export "X=$T"; sh -c 'curl -u "u:$X" x'`, refuse},
		{"env -, which clears the environment", "sh", `env - sh -c 'curl -u "u:$T" x'`, allow},
		{"stdout sent to stderr", "sh", `v=$(printf '%s' "$T" >&2); curl -u "u:$v" x`, allow},
		{"stdout and stderr sent to a file", "bash", `v=$(printf '%s' "$T" &>/dev/null); curl -u "u:$v" x`, allow},
		{"stderr sent to stdout", "sh", `v=$(printf '%s' "$T" 2>&1); curl -u "u:$v" x`, refuse},
		{"stderr sent to stdout around a command that writes there", "dash", `v=$( { printf '%s' "$T" >&2; } 2>&1 ); curl -u "u:$v" x`, refuse},
		{"stderr sent to stdout, then stdout elsewhere", "sh", `v=$( { printf '%s' "$T" >&2; } 2>&1 >/dev/null ); curl -u "u:$v" x`, refuse},
		{"stdout sent elsewhere, then stderr after it", "sh", `v=$( { printf '%s' "$T" >&2; } >/dev/null 2>&1 ); curl -u "u:$v" x`, allow},
		{"a function's stderr sent to stdout", "sh", `f() { printf '%s' "$T" >&2; }; v=$(f 2>&1); curl -u "u:$v" x`, refuse},
		{"exec 2>&1, which sends stderr to stdout for the commands after it", "dash", `v=$(exec 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"exec 2>&1 in a group, which lasts after it", "sh", `v=$( { exec 2>&1; }; printf '%s' "$T" >&2 ); curl -u "u:$v" x`, refuse},
		{"exec 2>&1 in a function", "bash", `f() { exec 2>&1; }; v=$(f; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"exec 2>&1 in eval's code", "zsh", `v=$(eval 'exec 2>&1'; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"exec 2>&1 in a subshell, which ends with it", "sh", `v=$( (exec 2>&1); printf '%s' "$T" >&2 ); curl -u "u:$v" x`, allow},
		{"exec 2>&1 in a group whose stdout goes elsewhere", "bash", `v=$( { exec 2>&1; } >/dev/null; printf '%s' "$T" >&2 ); curl -u "u:$v" x`, allow},
		// exec adds where output goes, and keeps where it went: it may not have
		// run, its file may not open, or a later exec may bring it back.
		{"exec 2>/dev/null after exec 2>&1, refused though it sends stderr elsewhere", "sh", `v=$(exec 2>&1; exec 2>/dev/null; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null, refused though it sends stdout elsewhere", "zsh", `v=$(exec >/dev/null; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null after &&, which may not run it", "sh", `v=$([ -n "$Q" ] && exec >/dev/null; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null after ||", "zsh", `v=$([ -z "$Q" ] || exec >/dev/null; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null in a branch", "bash", `v=$(if [ -n "$Q" ]; then exec >/dev/null; fi; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null in a case arm", "dash", `v=$(case "$Q" in y) exec >/dev/null;; esac; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null in a loop that runs no pass", "sh", `v=$(for i in $NONE; do exec >/dev/null; done; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null after break", "dash", `v=$(for i in 1; do break; exec >/dev/null; done; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null after return", "sh", `f() { return; exec >/dev/null; }; v=$(f; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null in a function a branch calls", "bash", `q() { exec >/dev/null; }; v=$([ -n "$Q" ] && q; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null in eval's code after &&", "sh", `v=$([ -n "$Q" ] && eval 'exec >/dev/null'; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null in a pipeline, which runs it in a subshell", "dash", `v=$(exec >/dev/null | :; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >/dev/null in the background", "sh", `v=$(exec >/dev/null & printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec >&- after &&", "dash", `v=$([ -n "$Q" ] && exec >&-; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec 2>/dev/null after && in a group sent to stdout", "zsh", `v=$( { [ -n "$Q" ] && exec 2>/dev/null; printf '%s' "$T" >&2; } 2>&1 ); curl -u "u:$v" x`, refuse},
		{"exec >&3, which brings back the stdout exec 3>&1 saved", "sh", `v=$(exec 3>&1 >/dev/null; exec >&3; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec to a file bash cannot open, which leaves stdout", "bash", `v=$(exec >/nonexistent/out.log; printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"exec 2>&1 in a loop, before a later pass writes to stderr", "dash", `v=$(for i in 1 2; do printf '%s' "$T" >&2; exec 2>&1; done); curl -u "u:$v" x`, refuse},
		{"command exec 2>&1", "sh", `v=$(command exec 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"exec in quotes", "zsh", `v=$("exec" 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"exec --", "bash", `v=$(exec -- 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"an alias of exec", "dash", "alias e=exec\nv=$(e 2>&1; printf '%s' \"$T\" >&2); curl -u \"u:$v\" x", refuse},
		{"exec of words that may expand to none", "sh", `v=$(exec $NONE 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"a name made as the script runs, which may be exec", "dash", `e=exec; v=$($e 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"a function a name made as the script runs names, whose exec lasts", "sh", `f() { exec 2>&1; }; e=f; v=$($e; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"the same by a name made of a prefix, in a group piped to xargs", "zsh", `quiet_on() { exec 2>&1; }; m=on; { "quiet_$m"; printf '%s\n' "$T" >&2; } | xargs curl -s -H`, refuse},
		{"command of a name made as the script runs, which may be exec", "dash", `e=exec; v=$(command $e 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"zsh's command of one, which runs a program", "zsh", `e=exec; v=$(command $e 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, allow},
		{"zsh's builtin of one, which may be exec", "zsh", `e=exec; v=$(builtin "$e" 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, refuse},
		{"builtin of one, which may be command, which runs a program", "bash", `e=command; builtin $e curl -u "u:$T" x`, refuse},
		{"exec of a word that is always one, as \"$NONE\" is", "sh", `v=$(exec "$NONE" 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, allow},
		{"a function whose exec has no redirections, which keeps none of the call's", "bash", `f() { exec; }; v=$(f 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, allow},
		{"stdout written to /dev/stdout", "sh", `v=$(printf '%s' "$T" > /dev/stdout); curl -u "u:$v" x`, refuse},
		{"stdout written to a path the script makes, which may be /dev/stdout", "sh", `o=/dev/stdout; v=$(printf '%s' "$T" > "$o"); curl -u "u:$v" x`, refuse},
		{"stdout written to a file the script names as it runs", "sh", `v=$(printf '%s' "$T" > "$HOME/out.txt"); curl -u "u:$v" x`, allow},
		{"stdout written to /dev/stderr, sent to stdout", "zsh", `v=$( { printf '%s' "$T" > /dev/stderr; } 2>&1 ); curl -u "u:$v" x`, refuse},
		{"|&, which pipes stderr too", "zsh", `{ printf '%s\n' "$T" >&2; } |& xargs -I{} curl -H "X: {}" x`, refuse},
		{"a pipe, which takes no stderr", "sh", `{ printf '%s\n' "$T" >&2; } | xargs -I{} curl -H "X: {}" x`, allow},
		{"a read from /dev/stdin", "sh", `{ read -r v </dev/stdin; curl -u "u:$v" x; } <<< "$T"`, refuse},
		{"a read from /dev/fd/0", "zsh", `{ read -r v </dev/fd/0; curl -u "u:$v" x; } <<< "$T"`, refuse},
		{"a read from the path of a descriptor exec opened", "bash", `exec 3<<<"$T"; read -r v < /dev/fd/3; curl -u "u:$v" x`, refuse},
		{"a read from a path the script makes, which may be /dev/stdin", "sh", "p=/dev/stdin; { read -r v < \"$p\"; curl -u \"u:$v\" x; } <<EOF\n$T\nEOF", refuse},
		{"a read from a path the script makes of a descriptor exec opened", "bash", `exec 3<<<"$T"; n=3; read -r v < "/dev/fd/$n"; curl -u "u:$v" x`, refuse},
		{"a read from a file the script names as it runs", "bash", `{ read -r v < "$HOME/.config/user"; curl -u "u:$v" x; } <<< "$T"`, allow},
		{"a program given a file the script names as it runs, which may be stdin", "sh", `f=-; X=$(printf '%s' "$T" | cat "$f"); curl -H "X-Key: $X" x`, refuse},
		{"a program given a path the script makes of a descriptor exec opened", "bash", `exec 3<<<"$T"; n=3; v=$(cat "/dev/fd/$n"); curl -u "u:$v" x`, refuse},
		{"$(<FILE), which is what FILE holds", "bash", `{ curl -u "u:$(</dev/stdin)" x; } <<< "$T"`, refuse},
		{"$(<FILE) in dash, which runs no command", "dash", "{ curl -u \"u:$(</dev/stdin)\" x; } <<EOF\n$T\nEOF", allow},
		{"cat of a descriptor's path", "bash", `v=$(cat /dev/fd/3 3<<<"$T"); curl -u "u:$v" x`, refuse},
		{"cat of the path of a descriptor exec opened", "bash", `exec 3<<<"$T"; v=$(cat /dev/fd/3); curl -u "u:$v" x`, refuse},
		{"what a command writes to >(...), which reads it", "bash", `printf '%s\n' "$T" > >(xargs -I{} curl -H "X: {}" x)`, refuse},
		{">(...) writing to the substitution around it", "zsh", `v=$(printf '%s' "$T" > >(cat)); curl -u "u:$v" x`, refuse},
		{"output sent past >(...) in bash", "bash", `printf '%s\n' "$T" > >(xargs -I{} curl -H "X: {}" x) >/dev/null`, allow},
		{"what a later command writes to a >(...) exec opened", "bash", `v=$(exec > >(cat); printf '%s' "$T"); curl -u "u:$v" x`, refuse},
		{"stderr sent to a >(...) exec opened", "zsh", `exec 2> >(xargs -I{} curl -H "X: {}" x); printf '%s\n' "$T" >&2`, refuse},
		{"output a >(...) exec opened leaves on stdin", "bash", `exec > >(tee -a ./log.txt) 2>&1; printf 'user = "u:%s"\n' "$T" | curl -s -K - x`, allow},
		{"output sent to >(...) and a file in zsh, which writes to both", "zsh", `printf '%s\n' "$T" > >(xargs -I{} curl -H "X: {}" x) >/dev/null`, refuse},
		{"a >(...) that eval opens again on each pass of a loop, which then settles", "bash", `for i in 1 2 3; do eval 'exec > >(cat >/dev/null)'; done; printf 'user = "u:%s"\n' "$T" | curl -K - x`, allow},
		{"what a later command writes to a >(...) that eval opens on each call", "zsh", `f() { eval 'exec > >(xargs curl -s -H)'; }; f; f; f; printf '%s\n' "$T"; wait`, refuse},

		// Programs and builtins that print what the environment holds.
		{"printenv", "sh", `curl -H "X: $(printenv)" x`, refuse},
		{"printenv of another variable", "sh", `curl -H "X: $(printenv OTHER)" x`, allow},
		{"env alone", "sh", `curl -H "X: $(env)" x`, refuse},
		{"env -i alone", "sh", `curl -H "X: $(env -i)" x`, allow},
		{"envsubst", "sh", `curl -d "$(envsubst < body.json)" x`, refuse},
		{"export -p", "sh", `curl -H "X: $(export -p)" x`, refuse},
		{"declare -p of the variable", "bash", `curl -H "X: $(declare -p T)" x`, refuse},
		{"declare -p of another", "bash", `curl -H "X: $(declare -p OTHER)" x`, allow},
		{"declare -p alone", "bash", `curl -H "X: $(declare -p)" x`, refuse},
		{"set alone", "sh", `curl -H "X: $(set)" x`, refuse},
		{"jq's $ENV", "sh", `curl -H "X: $(jq -rn '$ENV.T')" x`, refuse},
		{"jq's env alone", "sh", `curl -H "X: $(jq -rn env)" x`, refuse},
		{"a jq field named env", "sh", `curl -H "X: $(jq -r .env config.json)" x`, allow},
		{"awk's ENVIRON", "sh", `curl -H "X: $(awk 'BEGIN { print ENVIRON["T"] }')" x`, refuse},
		{"awk's ENVIRON of another", "sh", `curl -H "X: $(awk 'BEGIN { print ENVIRON["OTHER"] }')" x`, allow},
		{"a shell that prints the value", "sh", `curl -H "X: $(sh -c 'echo "$T"')" x`, refuse},
		{"gh's other output", "sh", `curl -H "X: $(gh auth status)" x`, allow},

		// Builtins, programs, functions and aliases.
		{"an alias to the builtin", "sh", "alias p=printf\np '%s' \"$T\" | curl -K - x", allow},
		{"an alias, where the name is quoted", "sh", "alias printf=/usr/bin/printf\n\\printf '%s' \"$T\" | curl -K - x", allow},
		{"an alias in bash after shopt -s expand_aliases", "bash", "shopt -s expand_aliases\nalias printf=/usr/bin/printf\nprintf '%s' \"$T\" | curl -K - x", refuse},
		{"an alias whose text expands the value", "sh", "alias jc='curl -u \"u:$T\"'\njc x", refuse},
		{"the same in bash, which expands no alias", "bash", "alias jc='curl -u \"u:$T\"'\njc x", allow},
		{"an alias of no text, which leaves the command's other words", "dash", "alias x=''\nx curl -u \"u:$T\" x", refuse},
		{"an alias of two commands", "sh", "alias jc='cd /tmp; curl -u \"u:$T\"'\njc x", refuse},
		{"an alias that keeps its own name", "sh", "alias curl='curl -s'\ncurl -u \"u:$T\" x", refuse},
		{"an alias whose command reads the value on stdin", "sh", "alias jc='curl -s -K -'\nprintf '%s' \"$T\" | jc x", allow},
		{"an alias given the value in its text", "dash", `alias jc='curl -u u:'"$T"`, refuse},
		{"an alias whose text starts with another alias", "sh", "alias b='curl -u \"u:$T\"'\nalias a='b'\na x", refuse},
		{"aliases that name each other", "dash", "alias a='b'\nalias b='a'\nprintf '%s' \"$T\" | a", allow},
		{"an alias whose text ends in a blank, which makes the next word an alias", "dash", "alias run='nohup '\nalias jc='curl -u \"u:$T\"'\nrun jc x", refuse},
		{"an alias whose text ends in no blank", "sh", "alias run='nohup'\nalias jc='curl -u \"u:$T\"'\nrun jc x", allow},
		{"zsh's eval, which expands aliases as it runs", "zsh", `alias jc='curl -u "u:$T"'; eval 'jc x'`, refuse},
		{"a function zsh's eval defines, whose aliases it expands", "zsh", `alias jc='curl -u "u:$T"'; eval 'f() { jc x; }'; f`, refuse},
		{"zsh's trap, which expands aliases as it runs", "zsh", `alias jc='curl -u "u:$T"'; trap 'jc x' EXIT; :`, refuse},
		{"a function zsh read with the script, which eval calls", "zsh", `alias jc='curl -u "u:$T"'; f() { jc x; }; eval f`, allow},
		{"enable without -n", "bash", `enable printf; printf '%s' "$T" | curl -K - x`, allow},
		{"zsh's disable -f, which turns off functions", "zsh", `disable -f f; printf '%s' "$T" | curl -K - x`, allow},
		{"command -v, which only looks a name up", "sh", `command -v curl "$T" >/dev/null && curl -s x`, allow},
		{"command after --", "sh", `command -- printf '%s' "$T" | curl -K - x`, allow},
		{"command of a program", "sh", `command curl -u "u:$T" x`, refuse},
		{"builtin of a program, which runs nothing", "bash", `builtin curl -u "u:$T" x`, allow},
		{"exec of a program after --", "sh", `exec -- curl -u "u:$T" x`, refuse},
		{"exec -a, which names a shell but leaves it its script", "bash", `exec -a x bash -c 'curl -u "u:$T" x'`, refuse},
		{"zsh's exec -a", "zsh", `exec -a x sh -c 'curl -u "u:$T" x'`, refuse},
		{"exec -a of a shell whose script keeps the value out", "sh", `exec -a x bash -c 'printf "%s" "$T" | curl -K - x'`, allow},
		{"zsh's -O, a flag, in front of -c", "sh", `zsh -Oc 'curl -u "u:$T" x' 'echo harmless'`, refuse},
		{"zsh's -o with its option's name in the same word", "bash", `zsh -opipefail -c 'curl -u "u:$T" x'`, refuse},
		{"a launcher's --", "sh", `nohup -- curl -u "u:$T" x`, refuse},
		{"zsh's noglob", "zsh", `noglob curl -u "u:$T" x`, refuse},
		{"trap -p, which prints", "sh", `trap -p EXIT; printf '%s' "$T" | curl -K - x`, allow},
		{"a trap that runs on exit after an assignment", "sh", `trap 'curl -u "u:$H" x' EXIT; H=$T`, refuse},
		{"trap after --", "sh", `trap -- 'curl -u "u:$T" x' EXIT`, refuse},
		{"trap given no condition, which sets nothing", "sh", `trap 'curl -u "u:$T" x'`, allow},
		{"a function that calls itself", "sh", `f() { f; curl -u "u:$1" x; }; f "$T"`, refuse},
		{"a function that calls itself with the value in a new place", "sh", `f() { if [ -n "$2" ]; then curl -u "u:$2" x; else f a "$1"; fi; }; f "$T"`, refuse},
		{"a function that calls itself once it has set a copy", "sh", `f() { curl -H "X: $G" x; [ -n "$G" ] && return; G=$T; f; }; f`, refuse},
		{"a function that calls itself on the rest of its parameters", "sh", `f() { [ "$#" -gt 0 ] || return; printf '%s' "$1" | curl -K - x; shift; f "$@"; }; f "$T" "$T"`, allow},
		{"a function a variable names", "sh", `api() { curl -H "Authorization: Bearer $T" "x/$1"; }; f=api; $f issues`, refuse},
		{"a function a name made in a loop names", "sh", `get_issues() { curl -u "u:$T" x; }; for e in issues; do "get_$e"; done`, refuse},
		{"a function a name made in a loop cannot name", "sh", `put_issues() { curl -u "u:$T" x; }; for e in issues; do "get_$e"; done`, allow},
		{"a function defined again after a call", "sh", `f() { curl -u "u:$1" x; }; f "$T"; f() { printf '%s' "$1"; }`, refuse},
		{"a zsh function of two names", "zsh", `function f g { curl -u "u:$1" x }; g "$T"`, refuse},
		{"zsh's anonymous function, which runs at once", "zsh", `() { curl -u "u:$T" x }`, refuse},
		{"a C-style loop", "bash", `for ((i = 0; i < 1; i++)); do curl -u "u:$T" x; done`, refuse},
		{"a coprocess", "bash", `coproc curl -u "u:$T" x`, refuse},
		{"an escaped dollar in a here-document a shell runs", "sh", "sh <<EOF\ncurl -u \"u:\\$T\" x\nEOF", refuse},

		// Code a variable holds.
		{"eval of a variable given code", "sh", `cmd='curl -u "u:$T" x'; eval "$cmd"`, refuse},
		{"eval of a variable and more words", "sh", `C='curl -H "Authorization: Bearer $T"'; eval "$C x"`, refuse},
		{"eval of a variable, unquoted", "sh", `cmd='curl -u "u:$T" x'; eval $cmd`, refuse},
		{"a local variable given code", "bash", `f() { local cmd='curl -u "u:$T" x'; eval "$cmd"; }; f`, refuse},
		{"code with an escaped dollar", "sh", `cmd="curl -u u:\$T x"; eval "$cmd"`, refuse},
		{"sh -c of a variable given code", "sh", `s='curl -u "u:$T" x'; sh -c "$s"`, refuse},
		{"sh -c of a here-document that cat prints", "sh", "bash -c \"$(cat <<'EOF'\ncurl -u \"u:$T\" x\nEOF\n)\"", refuse},
		{"a variable given a here-document that cat prints", "sh", "s=$(cat <<'EOF'\ncurl -u \"u:$T\" x\nEOF\n)\nsh -c \"$s\"", refuse},
		{"trap of a variable given code", "sh", `cmd='curl -u "u:$T" x'; trap "$cmd" EXIT`, refuse},
		{"watch of a variable given code", "sh", `cmd='curl -u "u:$T" x'; watch -n 5 "$cmd"`, refuse},
		{"eval of code that keeps the value out", "sh", `cmd='printf "%s" "$T" | curl -K - x'; eval "$cmd"`, allow},
		{"sh -c of code that keeps the value out", "sh", `cmd='printf "%s" "$T" | curl -K - x'; sh -c "$cmd"`, allow},
		{"code a loop gives a variable on every pass", "sh", `for i in 1 2 3 4 5 6; do cmd='curl -u "u:$T" x'; eval "$cmd"; done`, refuse},
		{"code a function gives a variable on every call", "sh", `f() { cmd='printf "%s" "$T" | curl -K - x'; eval "$cmd"; }; f; f; f; f; f; f`, allow},
	} {
		found, err := shell.Check(tc.shell, tc.script, []string{"T", "PIN"})
		if got := len(found) > 0; err != nil || got != tc.refuse {
			t.Errorf("%s: refused = %v, %v; want %v; found %s", tc.what, got, err, tc.refuse, brief(found))
		}
	}
}

// A program whose output is made of its input passes a value on, as each of
// these pipelines does on every shell.
func TestCheckFollowsAValueThroughProgramsThatPassItOn(t *testing.T) {
	for _, pipeline := range []string{
		"nl -ba | cut -f2", "column -t", "fmt", "expand", "unexpand", "pr -t", "base32 | base32 -d",
		"zstd -q | zstd -dq", "zstd -q | unzstd", "zstd -q | zstdcat", "lz4 -q | lz4 -dq", "lz4 -q | unlz4",
		"lz4 -q | lz4cat", "xz | unxz", "xz | xzcat", "bzip2 | bunzip2", "bzip2 | bzcat", "gzip | gzcat",
	} {
		script := `X=$(printf '%s\n' "$T" | ` + pipeline + `); curl -H "X-Key: $X" x`
		if found, err := shell.Check("sh", script, onlyT); err != nil || len(found) == 0 {
			t.Errorf("%s: found %s, %v; want the value in curl's command line", pipeline, brief(found), err)
		}
	}
}

// The words of a command in a pipeline expand reading the pipe, so a program
// in a substitution there gets the value only if it reads stdin: cat with no
// file to read does, as the shells show, and jq -n does not.
func TestCheckFollowsStdinOnlyIntoAProgramThatReadsIt(t *testing.T) {
	for _, tc := range []struct {
		substitution string
		refuse       bool
	}{
		{`$(jq -rn --arg q 'project = DW' '$q|@uri')`, allow},
		{`$(jq -n --arg s 'Fix it' '{fields: {summary: $s}}')`, allow},
		{`$(jq -c . body.json)`, allow},
		{`$(cat body.json)`, allow},
		{`$(sed -n 1p urls.txt)`, allow},
		{`$(head -n1 urls.txt)`, allow},
		{`$(grep -e bin -m1 /etc/shells)`, allow},
		{`$(awk -F: 'NR == 1 { print $1 }' users.txt)`, allow},
		{`$(python3 -I -c 'import sys; print(open(sys.argv[1]).readline().strip())' urls.txt)`, allow},
		{`$(perl -e 'print "x"')`, allow},
		{`$(node -pe '1 + 1')`, allow},
		{`$(dd if=/dev/urandom bs=4 count=1 2>/dev/null | xxd -p)`, allow},
		{`$(openssl rand -hex 8)`, allow},
		{`$(cat)`, refuse},
		{`$(cat - urls.txt)`, refuse},
		{`$(cat /dev/stdin)`, refuse},
		{`$(cat $files)`, refuse},
		{`$(head -c 200)`, refuse},
		{`$(sed -n 1p)`, refuse},
		{`$(cut -d , -f 1)`, refuse},
		{`$(grep -e user)`, refuse},
		{`$(awk '{ print }' n=1)`, refuse},
		{`$(tail +1)`, refuse},
		{`$(jq -Rrn input)`, refuse},
		{`$(jq -R . --args a b)`, refuse},
		{`$(python3 -I -c 'import sys; print(sys.stdin.read())')`, refuse},
		{`$(python3 -I ./print.py)`, refuse},
		{`$(perl -ne 'print')`, refuse},
		{`$(ruby -e 'print gets')`, refuse},
		{`$(node -e 'process.stdin.pipe(process.stdout)')`, refuse},
		{`$(dd bs=200 count=1 2>/dev/null)`, refuse},
		{`$(base64)`, refuse},
		// A file the script names as it runs may be stdin, unless its name's
		// literal text rules that out.
		{`$(cat "$f")`, refuse},
		{`$(cat "${1:--}")`, refuse},
		{`$(cat "$(printf -)")`, refuse},
		{`$(cat "/dev/fd/$n")`, refuse},
		{`$(head -c 64 "$in")`, refuse},
		{`$(sed -n 1p "$f")`, refuse},
		{`$(jq -r . "$f")`, refuse},
		{`$(python3 -I -c 'import sys; print(open(sys.argv[1]).read())' "$f")`, refuse},
		{`$(dd if="$f" bs=64 count=1 2>/dev/null)`, refuse},
		{`$(openssl base64 -in "$f")`, refuse},
		{`$(cat "$HOME/.config/url.txt")`, allow},
		{`$(cat "./$name.txt")`, allow},
		{`$(jq -r .url "$HOME/.config/x.json")`, allow},
		{`$(dd if="$HOME/disk.img" bs=4 count=1 2>/dev/null | xxd -p)`, allow},
		{`$(openssl base64 -in ./key.pem)`, allow},
	} {
		script := `printf 'header = "X-Key: %s"\n' "$T" | curl -K - "https://x.example.com/` + tc.substitution + `"`
		found, err := shell.Check("sh", script, onlyT)
		if got := len(found) > 0; err != nil || got != tc.refuse {
			t.Errorf("%s: refused = %v, %v; want %v", tc.substitution, got, err, tc.refuse)
		}
	}
}

// The environment can hold a name that no shell expands, such as -1 or MY-KEY,
// which a project's .mcp.json can give a server; env still prints its value,
// and printenv MY-KEY reads it, so a script that names it, and that the check
// cannot follow to its end, is refused.
func TestCheckFollowsAValueUnderAnyName(t *testing.T) {
	for _, tc := range []struct {
		script string
		refuse bool
	}{
		{`curl https://x.example.com; sh -c 'curl -u "u:$1" x' _ "$1"`, allow},
		{`curl -H "X: $(env)" x`, refuse},
	} {
		found, err := shell.Check("sh", tc.script, []string{"-1"})
		if got := len(found) > 0; err != nil || got != tc.refuse {
			t.Errorf("%s: refused = %v, %v; want %v; found %s", tc.script, got, err, tc.refuse, brief(found))
		}
	}
	for _, tc := range []struct {
		script     string
		unreadable bool
	}{
		{`X=$(printenv MY-KEY); curl -u "u:$X" x`, true},
		{`X=$(env | grep '^MY-KEY=' | cut -d= -f2-); curl -u "u:$X" x`, true},
		{`X=$(printenv MY-OTHER); curl -u "u:$X" x`, false},
	} {
		found, err := shell.Check("sh", fanOut(60, ":")+tc.script, []string{"MY-KEY"})
		if (err != nil) != tc.unreadable || len(found) > 0 {
			t.Errorf("%s after functions that would take hours: found %s, error %v; want unreadable %v", tc.script, brief(found), err, tc.unreadable)
		}
	}
}

// What the check cannot see, as the README says: each of these puts the value
// in a command line, and runs.
func TestCheckMissesWhatTheREADMESaysItCannotSee(t *testing.T) {
	for _, tc := range []struct{ what, script string }{
		{"a script piped to a shell", "cat <<'EOF' | sh\ncurl -u \"u:$T\" x\nEOF"},
		{"a script printed to a shell", `printf '%s\n' 'curl -u "u:$T" x' | sh`},
		{"a script file", `sh ./deploy.sh`},
		{"a sourced file", `. ./env.sh; curl -u "u:$TOKEN_FROM_FILE" x`},
		{"code made as the script runs", `eval "$(cat ./cmd.sh)"`},
		{"another language's code", `python3 -c 'import os, subprocess; subprocess.run(["curl", "-u", "u:" + os.environ["T"], "x"])'`},
		{"a program that fills in its environment", `env -S 'curl -u u:${T} x'`},
		{"a value written to a file and read back", `printf '%s' "$T" > f; curl -u "u:$(cat f)" x`},
	} {
		if found, err := shell.Check("sh", tc.script, onlyT); err != nil || len(found) > 0 {
			t.Errorf("%s: found %s, %v; the gap is closed, so move the case to the refused ones", tc.what, brief(found), err)
		}
	}
}

// What the check does not follow, as the package says: output sent through
// another descriptor, an alias the script defines again, zsh's global
// aliases, and what trap's code writes. Each of these puts the value in a
// command line on its shell, and runs.
func TestCheckMissesWhatThePackageSaysItDoesNotFollow(t *testing.T) {
	for _, tc := range []struct{ what, shell, script string }{
		{"stdout that exec 3>&1 saved", "sh", `v=$(exec 3>&1; printf '%s' "$T" >&3); curl -u "u:$v" x`},
		{"stdout that 3>&1 saved for a group", "dash", `v=$( { printf '%s' "$T" >&3; } 3>&1 ); curl -u "u:$v" x`},
		{"stdout saved before exec >/dev/null", "bash", `v=$(exec 3>&1 >/dev/null; printf '%s' "$T" >&3); curl -u "u:$v" x`},
		{"stdout and stderr swapped through 3", "zsh", `v=$( { printf '%s' "$T" >&2; } 3>&1 1>&2 2>&3 ); curl -u "u:$v" x`},
		{"the same swap by exec", "sh", `v=$(exec 3>&1 1>&2 2>&3; printf '%s' "$T" >&2); curl -u "u:$v" x`},
		{"stdout saved outside a substitution and brought back in it", "dash", `v=$(exec 3>&1 >/dev/null; w=$(exec >&3; printf '%s' "$T")); curl -u "u:$v" x`},
		{"a >(...) that exec opened on 3", "bash", `exec 3> >(xargs curl -H); printf '%s\n' "$T" >&3; wait`},
		{"an alias defined again in a branch that does not run", "dash", "alias jc='curl -u \"u:$T\"'\n[ -n \"$NEVER\" ] && alias jc=true\njc x"},
		{"an alias defined again after a function that uses it", "sh", "alias jc='curl -u \"u:$T\"'\nf() { jc x; }\nalias jc=true\nf"},
		{"zsh's global alias", "zsh", `alias -g CRED='-u "u:$T"'; eval 'curl CRED x'`},
		{"what an EXIT trap's code writes", "sh", `v=$(trap 'printf %s "$T"' EXIT; :); curl -u "u:$v" x`},
		{"the same in a subshell piped to xargs", "dash", `( trap 'printf "%s\n" "$T"' EXIT; : ) | xargs curl -s -H`},
	} {
		if found, err := shell.Check(tc.shell, tc.script, onlyT); err != nil || len(found) > 0 {
			t.Errorf("%s: found %s, %v; the gap is closed, so move the case to the refused ones", tc.what, brief(found), err)
		}
	}
}

// FuzzCheck checks scripts that go test -fuzz makes from the case table's, in
// the shell which picks, with the variables names lists. Check must not
// panic; a finding names a resolved variable, a program and a line; only a
// script with a $ or a resolved variable's name can name a value, and so be
// refused as unreadable; and the refusal has a hint.
func FuzzCheck(f *testing.F) {
	shells := []string{"sh", "bash", "dash", "zsh"}
	add := func(sh, script string, resolved []string) {
		f.Add(uint8(slices.Index(shells, sh)), script, strings.Join(resolved, ","))
	}
	for _, tc := range scripts {
		add(tc.shell, tc.script, tc.resolved)
	}
	for _, tc := range commandLines {
		if sh, script, ok := shell.Command(tc.argv); ok {
			add(sh, script, tc.resolved)
		}
	}
	// Scripts the check once crashed on, took hours or gigabytes over, or let
	// through.
	add("sh", `set -- a "$T"; shift -2; curl -u "u:$2" x`, onlyT)
	add("sh", "shift 10000000000000000000", onlyT)
	add("zsh", "0", []string{"-1"})
	add("sh", loopChain(9, "$T"), onlyT)
	add("sh", fanOut(30, `curl -u "u:$T" x`), onlyT)
	add("sh", callChain(20, "$T"), onlyT)
	add("sh", `f() { eval "$1"; }; f 'curl -u "u:$T" x'`, onlyT)
	add("sh", "cmd='x=$(("+strings.Repeat("(", 4096)+"1"+strings.Repeat(")", 4096)+"))'\n"+fanOut(20, `eval "$cmd"`), onlyT)
	add("bash", `v=$(exec > >(cat); printf '%s' "$T"); curl -u "u:$v" x`, onlyT)
	add("dash", "alias run='nohup '\nalias b='curl -u \"u:$T\"'\nalias a='b'\nrun a x", onlyT)
	add("sh", doubling(24, `printf %s "$T" | wc -c`), onlyT)
	add("sh", `v=$([ -n "$Q" ] && exec >/dev/null; printf '%s' "$T"); curl -u "u:$v" x`, onlyT)
	add("sh", `v=$(command exec 2>&1; printf '%s' "$T" >&2); curl -u "u:$v" x`, onlyT)
	add("bash", fanOut(30, ":")+`X=$(printenv MY-KEY); curl -u "u:$X" x`, []string{"MY-KEY"})
	add("sh", `f() { exec 2>&1; }; e=f; v=$($e; printf '%s' "$T" >&2); curl -u "u:$v" x`, onlyT)
	add("dash", `e=eval; $e 'curl -u "u:$T" x'`, onlyT)
	add("bash", "x='exec > >(:)'\nf() { eval \"$x\"; }\n"+strings.Repeat("f\n", 40)+`curl -u "u:$T" x`, onlyT)
	add("zsh", strings.Repeat("exec > >(:)\n", 20)+strings.Repeat(":\n", 20)+`curl -u "u:$T" x`, onlyT)
	f.Fuzz(func(t *testing.T, which uint8, script, names string) {
		resolved := strings.Split(names, ",")
		found, err := shell.Check(shells[int(which)%len(shells)], script, resolved)
		named := slices.ContainsFunc(resolved, func(name string) bool { return name != "" && strings.Contains(script, name) })
		if err != nil && !strings.Contains(script, "$") && !named {
			t.Errorf("a script with no $ and no resolved variable's name is unreadable: %v", err)
		}
		if err != nil && shell.Hint(err) == "" {
			t.Errorf("no hint for %v", err)
		}
		for _, x := range found {
			if !slices.Contains(resolved, x.Var) || x.Program == "" || x.Line < 1 {
				t.Errorf("finding %s in %q at line %d", x.Var, x.Program, x.Line)
			}
			shell.Advice(x, found)
		}
	})
}
