package migrate_test

import (
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/migrate"
)

func TestDetectSecrets(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"SPLUNK_MCP_TOKEN", "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9.abc.def"},
		{"GITHUB_TOKEN", "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ"},
		{"GH_PAT", "github_pat_11ABCDEFG0abcdefghijklmnop"},
		{"ATLASSIAN_MCP_AUTH", "Basic bm53b2tvbG8yNEBleGFtcGxlLmNvbTp0b2tlbg=="},
		{"AUTHORIZATION", "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"},
		{"OPENAI_API_KEY", "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"},
		{"ANTHROPIC_API_KEY", "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx"},
		{"AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"},
		{"AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"SLACK_BOT_TOKEN", "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOp"},
		{"GITLAB_TOKEN", "glpat-AbCdEfGhIjKlMnOpQrSt"},
		{"STRIPE_SECRET", "sk_live_AbCdEfGhIjKlMnOpQrStUvWx"},
		{"GOOGLE_API_KEY", "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234567"},
		{"VAULT_TOKEN", "hvs.AbCdEfGhIjKlMnOpQrStUvWxYz"},
		{"NPM_TOKEN", "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"},
		{"SIGNING_KEY", "-----BEGIN RSA PRIVATE KEY-----"},
		{"DB_PASSWORD", "correct-horse-battery-staple-9271"},
		{"CLIENT_SECRET", "AbCdEfGhIjKlMnOpQrStUvWxYz012345"},
		{"MY_SESSION_TOKEN", "9f8e7d6c5b4a39281706fedcba098765"},

		// A URL carrying credentials is a secret even though the name gives no hint.
		{"DATABASE_URL", "postgresql://dbuser:s3cretp4ss@db.internal:5432/dashweb"},
		{"REDIS_URL", "redis://default:AbCdEf123456@cache.internal:6379"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := migrate.Detect(tt.name, tt.value)
			if !got.Secret {
				t.Errorf("Detect(%q, %q).Secret = false, want true (reason: %s)", tt.name, tt.value, got.Reason)
			}
			if got.Reason == "" {
				t.Error("Reason is empty; a plan has to be able to explain itself")
			}
		})
	}
}

func TestDetectNonSecrets(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		// Ordinary settings.
		{"EDITOR", "vim"},
		{"VISUAL", "code --wait"},
		{"PAGER", "less"},
		{"LANG", "en_US.UTF-8"},
		{"LC_ALL", "en_US.UTF-8"},
		{"TERM", "xterm-256color"},
		{"HISTSIZE", "10000"},
		{"CLICOLOR", "1"},

		// Paths and path lists.
		{"PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
		{"GOPATH", "/Users/nnwokolo/go"},
		{"NVM_DIR", "/Users/nnwokolo/.nvm"},
		{"KUBECONFIG", "/Users/nnwokolo/.kube/config"},
		{"DOCKER_HOST", "unix:///var/run/docker.sock"},

		// SSH_AUTH_SOCK contains AUTH and a long random-looking path. It is the
		// trap the name heuristic would fall into, and migrating it breaks the
		// agent socket for every shell.
		{"SSH_AUTH_SOCK", "/private/tmp/com.apple.launchd.hK3mQ9vLpZ/Listeners"},

		// AWS_PROFILE selects a profile; it is not a credential.
		{"AWS_PROFILE", "dashweb"},
		{"AWS_REGION", "us-east-1"},
		{"AWS_DEFAULT_REGION", "us-west-2"},

		// Expansions cannot be literal secrets, whatever the name suggests.
		{"PATH", "$HOME/.local/bin:$PATH"},
		{"MY_TOKEN", "$OTHER_TOKEN"},
		{"SOME_KEY", "$(op read op://vault/item/field)"},
		{"BACKTICK_KEY", "`cat /tmp/token`"},

		// Already migrated: running twice must change nothing.
		{"SPLUNK_MCP_TOKEN", "cap://splunk-mcp-token"},

		// Nothing to move.
		{"EMPTY", ""},

		// Credential-ish name but a value too short to be one.
		{"TOKEN", "x"},
		{"API_KEY", "abc"},

		// Contains KEY as part of an unrelated word.
		{"KEYBOARD_LAYOUT", "us"},
		{"MONKEY_COUNT", "12"},

		// A URL with no credentials in it.
		{"API_ENDPOINT", "https://api.splunk.com/v2/synthetics"},

		// A colon list whose entries are not all paths is not a path list.
		{"MY_SPEC", "name:/opt/thing"},

		// A leading empty entry means "also the current directory". It is still a
		// path list, even though the value does not itself start with a slash.
		{"MY_PATH_LIST", ":/usr/local/bin:/usr/bin"},

		// An @ after the path means it is not a userinfo section.
		{"API_ENDPOINT2", "https://api.example.com/users/me@example.com"},

		// A URL with a bare username and no password is not a credential.
		{"GIT_REMOTE", "https://nwokolo24@github.com/veilux-lab/keyward.git"},

		// Prompt strings are full of punctuation but are not secrets.
		{"PROMPT", "%n@%m %~ "},
		{"PS1", "\\u@\\h:\\w\\$ "},
	}

	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			got := migrate.Detect(tt.name, tt.value)
			if got.Secret {
				t.Errorf("Detect(%q, %q).Secret = true, want false (reason: %s)", tt.name, tt.value, got.Reason)
			}
			if got.Reason == "" {
				t.Error("Reason is empty; a plan has to be able to explain a skip")
			}
		})
	}
}

// Randomness alone is not enough to move a value. A real ~/.zshrc had CPPFLAGS and
// an ECR registry host migrated on entropy, which would break every build that does
// not go through keyward. No list of safe names can be complete, so these are
// flagged for a human instead.
func TestDetectRandomLookingValuesAreOnlyPossible(t *testing.T) {
	tests := []struct{ name, value string }{
		{"MY_THING", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i"},
		{"CPPFLAGS", "-I/opt/homebrew/opt/openssl@3/include"},
		{"AWS_ECR_URI", "123456789012.dkr.ecr.us-west-2.amazonaws.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := migrate.Detect(tt.name, tt.value)
			if got.Secret {
				t.Errorf("Detect(%q).Secret = true, want entropy alone not to move it", tt.name)
			}
			if !got.Possible {
				t.Errorf("Detect(%q).Possible = false, want it flagged (reason: %s)", tt.name, got.Reason)
			}
		})
	}
}

// Possible is reserved for the uncertain case; a confident verdict either way must
// not carry it.
func TestDetectPossibleOnlyWhenUncertain(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"GITHUB_TOKEN", "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ"},
		{"EDITOR", "vim"},
		{"SSH_AUTH_SOCK", "/private/tmp/com.apple.launchd.hK3mQ9vLpZ/Listeners"},
	} {
		if migrate.Detect(c.name, c.value).Possible {
			t.Errorf("Detect(%q).Possible = true, want false", c.name)
		}
	}
}

// The reason is shown to a human deciding whether to approve a rewrite, so it has
// to say something specific rather than restate the verdict.
func TestDetectReasonsAreSpecific(t *testing.T) {
	cases := []struct {
		name, value, wantSubstring string
	}{
		{"GITHUB_TOKEN", "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRs", "ghp_"},
		{"DB_PASSWORD", "correct-horse-battery-staple-9271", "name"},
		{"MY_THING", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i", "entropy"},
		{"DATABASE_URL", "postgresql://u:p@h:5432/db", "URL"},
		// Not PATH, which the safe-name list catches first — correctly, since that
		// is a stronger reason than the shape of the value.
		{"MY_TOOL_DIR", "/usr/local/opt/mytool/bin", "path"},
		{"MY_TOKEN", "$OTHER", "expansion"},
		{"T", "cap://already", "reference"},
		{"AWS_PROFILE", "dashweb", "non-secret"},
	}
	for _, c := range cases {
		got := migrate.Detect(c.name, c.value)
		if !strings.Contains(strings.ToLower(got.Reason), strings.ToLower(c.wantSubstring)) {
			t.Errorf("Detect(%q, %q).Reason = %q, want it to mention %q",
				c.name, c.value, got.Reason, c.wantSubstring)
		}
	}
}

// Deriving the vault name from the variable name is what makes a migrated file
// readable: SPLUNK_MCP_TOKEN becomes cap://splunk-mcp-token.
func TestRefName(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"SPLUNK_MCP_TOKEN", "splunk-mcp-token", false},
		{"GITHUB_TOKEN", "github-token", false},
		{"lowercase_already", "lowercase-already", false},
		{"MixedCase", "mixedcase", false},
		{"WITH2DIGITS", "with2digits", false},
		{"A", "a", false},

		// A name that cannot become a valid reference must be reported, not
		// silently mangled into something that would collide.
		{"_LEADING", "", true},
		{"TRAILING_", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := migrate.RefName(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("RefName(%q) = %q, want an error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("RefName(%q) returned error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("RefName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
