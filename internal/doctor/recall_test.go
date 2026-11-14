package doctor_test

import (
	"encoding/base64"
	"fmt"
	"math"
	"math/rand/v2"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/vault"
)

// labelWords are the words doctor's labels and reasons are made of, now and on
// origin/main. A fake value shares no four characters in a row with them, so a
// label holding four of its value's characters can only have taken them from the
// value.
const labelWords = "the variable name suggests a credential, the value is a URL containing credentials, " +
	"the value begins with a known credential prefix, credential-shaped text keyward cannot move, " +
	"characters at bits of entropy per character, a random character token, hex characters, a UUID, " +
	"an AWS secret key, base64 key, characters of base64 data, mixing letters, digits and symbols, " +
	"named like a credential, a URL with a password, base64-encoded JSON, a JWT, runs of, " +
	"a GitHub token, a Stripe secret key, random tokens, values mixing, runs of hex characters, base64 keys"

// gen makes fake values from a fixed seed, so every run judges the same ones.
type gen struct{ *rand.Rand }

const (
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars   = "0123456789"
	hexChars     = "0123456789abcdef"
	symbolChars  = "!@#%^&*()-_=+[]{}:,.?~"
)

// pick returns n characters from alphabet, drawn again until want accepts them
// and they share no four characters in a row with labelWords.
func (g gen) pick(alphabet string, n int, want func(string) bool) string {
	for {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[g.IntN(len(alphabet))]
		}
		if s := string(b); want(s) && !sharesFour(s, labelWords) {
			return s
		}
	}
}

func (g gen) between(lo, hi int) int { return lo + g.IntN(hi-lo+1) }

func (g gen) oneOf(choices ...string) string { return choices[g.IntN(len(choices))] }

// mixed is a token of upper case, lower case and digits.
func (g gen) mixed(n int) string {
	return g.pick(upperLetters+lowerLetters+digitChars, n, func(s string) bool { return classes(s) == 3 })
}

// lowerDigits is a token of lower case and digits.
func (g gen) lowerDigits(n int) string {
	return g.pick(lowerLetters+digitChars, n, func(s string) bool {
		return strings.ContainsAny(s, digitChars) && strings.ContainsAny(s, lowerLetters)
	})
}

// oneCase is a token of lower case and digits, or of upper case and digits.
func (g gen) oneCase(n int) string {
	letters := g.oneOf(lowerLetters, upperLetters)
	return g.pick(letters+digitChars, n, func(s string) bool {
		return strings.ContainsAny(s, digitChars) && strings.ContainsAny(s, letters)
	})
}

// hex is n hex digits, letters and digits both.
func (g gen) hex(n int) string {
	return g.pick(hexChars, n, func(s string) bool { return strings.ContainsAny(s, "abcdef") && strings.ContainsAny(s, digitChars) })
}

// key is a key of size bytes in base64. One starting with /, or holding more than
// three, reads as a path in a comment.
func (g gen) key(size int) string {
	for {
		b := make([]byte, size)
		for i := range b {
			b[i] = byte(g.IntN(256))
		}
		if s := base64.StdEncoding.EncodeToString(b); !strings.HasPrefix(s, "/") && strings.Count(s, "/") <= 3 && !sharesFour(s, labelWords) {
			return s
		}
	}
}

// symbols is a password of letters, digits and symbols.
func (g gen) symbols(n int) string {
	return g.pick(upperLetters+lowerLetters+digitChars+symbolChars, n, func(s string) bool {
		return classes(s) == 3 && strings.ContainsAny(s, symbolChars)
	})
}

// passphraseWords share no four characters in a row with labelWords.
var passphraseWords = []string{"kettle", "mango", "zebra", "quiet", "river", "lamp", "orbit", "velvet", "cobalt", "maple",
	"harbor", "pixel", "tundra", "falcon", "ember", "lotus", "prism", "quartz", "willow", "saffron", "glacier", "meadow"}

// passphrase is words joined by sep, a third holding a placeholder's word, some
// ending in digits, drawn again where a separator joins four characters labelWords
// has, as " cha" of " changeme" is in " characters".
func (g gen) passphrase(sep string) string {
	for {
		words := make([]string, g.between(3, 5))
		for i := range words {
			words[i] = passphraseWords[g.IntN(len(passphraseWords))]
		}
		if g.IntN(3) == 0 {
			words[g.IntN(len(words))] = g.oneOf("changeme", "paste", "replace-me")
		}
		phrase := strings.Join(words, sep)
		if g.IntN(2) == 0 {
			phrase += sep + g.pick(digitChars, g.between(2, 4), func(string) bool { return true })
		}
		if !sharesFour(phrase, labelWords) {
			return phrase
		}
	}
}

// camelPhrase is capitalised words, with one or two digits after them, between
// two of them or before them, of 24 characters or more. With short set, a word
// but the last is one whose capitals run into the next word's, as I, A, OK, TV
// and USA do.
func (g gen) camelPhrase(short bool) string {
	for {
		words := make([]string, g.between(3, 5))
		for i := range words {
			w := passphraseWords[g.IntN(len(passphraseWords))]
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
		if short {
			words[g.IntN(len(words)-1)] = g.oneOf("I", "A", "OK", "TV", "USA")
		}
		digits := g.pick(digitChars, g.between(1, 2), func(string) bool { return true })
		at := []int{len(words), g.between(1, len(words)-1), 0}[g.IntN(3)]
		phrase := strings.Join(words[:at], "") + digits + strings.Join(words[at:], "")
		if len(phrase) >= 24 && !sharesFour(phrase, labelWords) {
			return phrase
		}
	}
}

// document is a link to a Google Doc, a Notion page or a Figma file.
func (g gen) document() string {
	return []string{
		"https://docs.google.com/document/d/1" + g.mixed(g.between(32, 43)) + "/edit",
		"https://www.notion.so/acme/Runbook-" + g.hex(32),
		"https://www.figma.com/design/" + g.mixed(22) + "/Checkout",
	}[g.IntN(3)]
}

// keyedDocument is a link to a document whose ID is shaped like a key, as a Google
// Doc's, a Drive folder's, a Notion page's, a gist's and a Loom video's are.
func (g gen) keyedDocument() string {
	return []string{
		"https://docs.google.com/document/d/1" + g.mixed(g.between(32, 43)) + "/edit",
		"https://drive.google.com/drive/folders/1" + g.mixed(32),
		"https://www.notion.so/acme/Runbook-" + g.hex(32),
		"https://gist.github.com/someone/" + g.hex(32),
		"https://www.loom.com/share/" + g.hex(32),
	}[g.IntN(5)]
}

// besideDocument is token joined to link, a link to a document, by what a
// document's ID is never written with, in another URL that follows it, or running
// into another URL's scheme.
func (g gen) besideDocument(link, token string) string {
	switch g.IntN(4) {
	case 0:
		return link + g.oneOf(",", ";", "|", ")") + "https://hooks.slack." + "com/services/T0ABCDEFG/B0ABCDEFG/" + token
	case 1:
		return link + g.oneOf(",", ";", "|", ")") + "https://api.example.com/v1/" + token
	case 2:
		return link + token + g.oneOf("https", "http", "s3") + "://example.com/next"
	}
	return link + g.oneOf(",", ";", "|", ")", "|key=", "&", "=", "+", "@", "!", "*", "~", "$", "%20", "%0A", "^", `\n`) + token
}

// password is what a connection string holds, of lo to hi characters, with a
// colon in it if colon is set.
func (g gen) password(lo, hi int, colon bool) string {
	pw := g.mixed(g.between(lo, hi))
	if colon {
		i := g.between(1, len(pw)-1)
		pw = pw[:i] + ":" + pw[i:]
	}
	return pw
}

// chosen is a password a person might choose, too short or too plain to look
// random: mixed case, lower case and digits, lower case alone, words, or mixed
// case with symbols flags are written in.
func (g gen) chosen() string {
	switch n := g.between(12, 19); g.IntN(5) {
	case 0:
		return g.mixed(n)
	case 1:
		return g.lowerDigits(g.between(12, 23))
	case 2:
		return g.pick(lowerLetters, n, func(string) bool { return true })
	case 3:
		return g.passphrase("-")
	default:
		return g.pick(upperLetters+lowerLetters+digitChars+"_.@%", n, func(s string) bool {
			return classes(s) == 3 && strings.ContainsAny(s, "_.@%")
		})
	}
}

// flagLists are lists of flags with a password in them, at %s.
var flagLists = []string{
	"--user=admin --password=%s",
	"--host=db.internal --port=5432 --username=app --password=%s",
	"-Xmx2g -Dspring.datasource.password=%s",
	"-Xms512m -Djavax.net.ssl.keyStorePassword=%s",
	"-Xmx1g -Djavax.net.ssl.trustStorePassword=%s",
	"-Dcom.sun.management.jmxremote.port=9010 -Dcom.sun.management.jmxremote.password=%s",
	"-Dorg.gradle.daemon=false -Dorg.gradle.project.signing.password=%s",
	"-Xmx512m -Ddb.password=%s",
	"-Xmx512m -Dapi.key=%s",
	"-Dhttp.proxyUser=alice -Dhttp.proxyPassword=%s",
	"-Xmx1g -Dgpg.passphrase=%s",
	"--max-old-space-size=4096 --api-key=%s",
	"-uadmin -p%s -hdb.internal",
	"--user=alice:%s --verbose",
}

// keyedFlags are lists of flags with a password, at %s, set as NAME=value inside a
// flag, as Docker's --env and --build-arg, Helm's --set and --set-string,
// Terraform's -var and -backend-config, Ansible's --extra-vars, alone or in a
// list, and Spark's --conf set one.
var keyedFlags = []string{
	"--rm --env=POSTGRES_PASSWORD=%s --network=host",
	"--rm --env=RABBITMQ_ERLANG_COOKIE=%s --network=host",
	"--rm -eRELEASE_COOKIE=%s --network=host",
	"--pull --build-arg=NPM_TOKEN=%s --no-cache",
	"--atomic --set=postgresql.auth.password=%s --wait",
	"--install --set-string=redis.password=%s --wait",
	"-var=db_password=%s -auto-approve",
	"-backend-config=password=%s -reconfigure",
	"--check --extra-vars=db_password=%s",
	"--check --extra-vars=env=prod,db_password=%s",
	`--check --extra-vars "db_password=%s env=prod"`,
	"--master=yarn --conf=spark.ssl.keyStorePassword=%s",
}

// attachedLogins are lists of flags with a user and a password, at the first and
// second %s, attached to a flag as curl's -u and -U, lftp's -u, redis-cli's -a,
// smbclient's -U and --user, and isql's -U and -P take them, or set on a flag
// whose name says user.
var attachedLogins = []string{
	"-u%s:%s --silent --show-error",
	"-hredis.internal -a%s:%s",
	"--user=%s:%s --verbose",
	"--user=%s%%%s --workgroup=CORP",
	"--proxy-user=%s:%s --proxy=proxy.internal:3128",
	"-U%s%%%s --workgroup=CORP",
	"-U%s:%s --proxy=proxy.internal:3128 --silent",
	"-u%s,%s --norc",
	"-U%s -P%s -Sledger-db.internal",
}

// login is a password a person might choose, or a PIN, which looks as a port
// does after a host.
func (g gen) login() string {
	if g.IntN(4) == 0 {
		return g.pick(digitChars, g.between(6, 10), func(string) bool { return true })
	}
	return g.chosen()
}

// withEquals is a password a person might choose with = in it, and perhaps a
// character flags are not written in.
func (g gen) withEquals() string {
	return g.pick(upperLetters+lowerLetters+digitChars+"==!*~", g.between(10, 18), func(s string) bool {
		return classes(s) == 3 && strings.Contains(s, "=")
	})
}

// entropy is bits of entropy per character in s, as origin/main measured it.
func entropy(s string) float64 {
	counts := map[byte]float64{}
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	var bits float64
	for _, c := range counts {
		p := c / float64(len(s))
		bits -= p * math.Log2(p)
	}
	return bits
}

// random makes value only of what origin/main listed under a name that suggests
// no credential: 24 characters or more at 4 bits per character or more.
func random(value func(gen) string) func(gen) string {
	return func(g gen) string {
		for {
			if v := value(g); len(v) >= 24 && entropy(v) >= 4 {
				return v
			}
		}
	}
}

// recallShape is a shape of fake secret that origin/main listed, in the forms it
// listed it in, with the names it is written under.
type recallShape struct {
	what  string
	names []string
	value func(gen) string
	forms []recallForm
}

// A recallForm is how a fake secret is written: as line, of its name and the
// secret, in file.
type recallForm struct{ what, file, line string }

var (
	assignment   = recallForm{"an assignment", ".zshrc", "export %s='%s'"}
	envLine      = recallForm{".env line", ".env", "%s='%s'"}
	commentedOut = recallForm{"a commented-out export", ".zshrc", "# export %s='%s'"}
	bare         = recallForm{"a comment", ".zshrc", "# %[2]s"}
	note         = recallForm{"a note in a comment", ".zshrc", "# %s is %s"}
	trailer      = recallForm{"a comment beside a value", ".zshrc", "export EDITOR=vim # %[2]s"}

	// Most shapes were listed as assigned, and some alsoCommented.
	assigned      = []recallForm{assignment, envLine}
	alsoCommented = []recallForm{assignment, envLine, commentedOut}
)

// recallShapes are the shapes of a sweep of fake secrets, in the forms origin/main
// listed each in. Commented out, a value under a plain name was listed only where
// it is shaped like a key itself, as a mixed-case token or a base64 key is, so the
// rest are not written commented out. Under a plain name, a value is made only as
// random as one origin/main listed, by its own rule. Left out: a base64 key that
// reads as a path in a comment, as one starting with / does, a 32-byte key in
// base64 under a digest's name, which is written as a SHA-256 digest is, a token
// beside a document's ID under 30 characters and shaped like no key itself, and a
// passphrase separated by dots ending in a suffix hosts use, or a capability URL's
// token made only of letters, which looks exactly like a host name.
var recallShapes = []recallShape{
	{"a base64 key under a credential's name", []string{"ENCRYPTION_KEY", "SESSION_SECRET", "COOKIE_SECRET", "MASTER_KEY"},
		func(g gen) string { return g.key(32) }, alsoCommented},
	{"a base64 key under a plain name", []string{"LEDGER_SALT", "ASSET_SEED", "EXPORT_BLOB", "SYNC_NONCE"},
		random(func(g gen) string { return g.key(32) }), alsoCommented},
	{"a hex key under a credential's name", []string{"DATADOG_API_KEY", "SIGNING_SECRET", "MAILGUN_API_KEY", "SENTRY_AUTH_TOKEN"},
		func(g gen) string { return g.hex([]int{32, 40, 64}[g.IntN(3)]) }, alsoCommented},
	{"a mixed-case token under a plain name", []string{"SERVICE_ID", "BUILD_REF", "DEPLOY_HANDLE", "LICENSE_ID"},
		random(func(g gen) string { return g.mixed(g.between(32, 40)) }), alsoCommented},
	{"a mixed-case token under a credential's name", []string{"API_TOKEN", "CLIENT_SECRET", "ACCESS_TOKEN"},
		func(g gen) string { return g.mixed(g.between(32, 40)) }, alsoCommented},
	{"a lowercase-and-digit token under a plain name", []string{"CI_JOB_SEED", "WORKER_HANDLE", "RUNNER_ID"},
		random(func(g gen) string { return g.lowerDigits(g.between(36, 44)) }), assigned},
	{"a lowercase-and-digit token under a credential's name", []string{"BUILDKITE_TOKEN", "NETLIFY_AUTH_TOKEN", "APP_SECRET"},
		func(g gen) string { return g.lowerDigits(g.between(26, 40)) }, alsoCommented},
	{"a symbol password under a credential's name", []string{"DB_PASSWORD", "ADMIN_PASS", "SMTP_PASSWORD", "REDIS_PASSWORD"},
		func(g gen) string { return g.symbols(g.between(14, 28)) }, alsoCommented},
	{"a symbol password under a plain name", []string{"DB_CONN_STRING", "LEDGER_LOGIN", "VPN_PHRASE"},
		random(func(g gen) string { return g.symbols(g.between(24, 32)) }), assigned},
	{"a word passphrase", []string{"DB_PASSWORD", "GPG_PASSPHRASE", "VAULT_PASS", "ADMIN_PASSWORD", "KEYSTORE_PASSWORD"},
		func(g gen) string { return g.passphrase("-") }, alsoCommented},
	{"a word passphrase under a plain name", []string{"NAS_LOGIN", "WIFI_PHRASE", "DISK_UNLOCK", "VAULT_PHRASE"},
		random(func(g gen) string { return g.passphrase(g.oneOf("-", "_", " ")) }), assigned},
	// Separated by dots, as 1Password and Bitwarden can, one is written as a host is.
	{"a passphrase separated by dots", []string{"NAS_LOGIN", "WIFI_PHRASE", "DISK_UNLOCK", "VAULT_PHRASE"},
		random(func(g gen) string { return g.passphrase(".") }), assigned},
	{"a list of URLs with passwords", []string{"NATS_SERVERS", "AMQP_CLUSTER", "REPLICA_URLS", "CACHE_NODES"},
		func(g gen) string {
			urls := make([]string, g.between(2, 3))
			for i := range urls {
				scheme := g.oneOf("postgres", "redis", "amqp", "nats", "mongodb")
				urls[i] = fmt.Sprintf("%s://%s:%s@%s-%d.internal:%d", scheme, g.oneOf("app", "svc", "ledger"), g.password(12, 18, false), scheme, i+1, g.between(1024, 9999))
			}
			return strings.Join(urls, ",")
		}, alsoCommented},
	{"a header list with a short key", []string{"OTEL_EXPORTER_OTLP_HEADERS"},
		random(func(g gen) string {
			return "x-honeycomb-team=" + g.mixed(g.between(12, 20)) + ",x-honeycomb-dataset=checkout"
		}), assigned},
	{"a pgpass line", []string{"PGPASS_LINE", "LEDGER_PGPASS"},
		random(func(g gen) string {
			return g.oneOf("ledger-db.internal", "orders-db.internal", "*") + ":" + g.oneOf("5432", "*") + ":ledger:ledger_app:" + g.password(12, 22, false)
		}), assigned},
	{"a token under a digest's name", []string{"BACKUP_HASH", "ASSET_SHA", "RELEASE_DIGEST", "BUNDLE_ETAG", "LOCKFILE_INTEGRITY", "BUILD_COMMIT"},
		random(func(g gen) string {
			switch g.IntN(3) {
			case 0:
				return g.mixed(g.between(32, 40))
			case 1:
				return g.lowerDigits(g.between(26, 44))
			}
			return g.key(24)
		}), assigned},
	{"a key under a digest's name with HMAC or SIGNING", []string{"LEDGER_HMAC_SHA256", "PAYLOAD_SIGNING_DIGEST", "EVENTS_HMAC_SHA", "RELEASE_SIGNING_HASH"},
		random(func(g gen) string { return g.key(32) }), alsoCommented},
	{"a MySQL DSN", []string{"MYSQL_DSN", "ORDERS_DSN"},
		random(func(g gen) string {
			return "app:" + g.password(12, 18, g.IntN(2) == 0) + "@tcp(db.internal:3306)/" + g.oneOf("orders", "ledger", "payments")
		}), assigned},
	{"a Kafka login", []string{"KAFKA_SASL", "KAFKA_LOGIN"},
		random(func(g gen) string { return "svc-orders:" + g.password(12, 18, g.IntN(2) == 0) + "@kafka.internal:9092" }), assigned},
	{"a DSN over a socket", []string{"DB_DSN", "LOCAL_DSN"},
		random(func(g gen) string {
			return "user:" + g.password(12, 22, g.IntN(2) == 0) + "@/" + g.oneOf("orders", "ledger")
		}), assigned},
	{"an Oracle thin URL to a service", []string{"ORACLE_URL", "LEDGER_JDBC_URL"},
		random(func(g gen) string {
			return "jdbc:oracle:thin:ledger_app/" + g.password(12, 18, false) + "@ledger-db.internal:1521/LEDGERPDB"
		}), assigned},
	{"an Oracle thin URL to a SID", []string{"ORACLE_URL", "LEDGER_JDBC_URL"},
		random(func(g gen) string {
			return "jdbc:oracle:thin:ledger_app/" + g.password(12, 18, false) + "@ledger-db.internal:1521:ORCL"
		}), assigned},
	{"an Oracle thin URL to a TNS alias", []string{"ORACLE_URL", "LEDGER_JDBC_URL"},
		random(func(g gen) string {
			return "jdbc:oracle:thin:ledger_app/" + g.password(12, 18, false) + "@LEDGERPDB_HIGH"
		}), assigned},
	{"a Django key", []string{"DJANGO_SECRET_KEY", "SECRET_KEY"},
		func(g gen) string {
			key := g.pick(lowerLetters+digitChars+"!@#%^&*(-_=+)", 50, func(string) bool { return true })
			if g.IntN(2) == 0 {
				return "django-insecure-" + key
			}
			return key
		}, alsoCommented},
	{"a capability URL with no scheme", []string{"NTFY_TOPIC_URL", "INGEST_ENDPOINT", "EVENTS_SINK", "PIPEDREAM_HOST"},
		random(func(g gen) string {
			switch g.IntN(5) {
			case 0:
				return "ntfy.sh/" + g.lowerDigits(g.between(16, 23))
			case 1:
				return "hooks.internal.example.com/ingest/" + g.lowerDigits(g.between(16, 23))
			case 2:
				return "hooks.internal.example.com/ingest/" + g.hex(g.between(24, 31))
			case 3:
				return "hooks.internal.example.com/ingest/" + g.lowerDigits(g.between(8, 15))
			}
			return "eo" + g.lowerDigits(g.between(13, 15)) + ".m.pipedream.net"
		}), assigned},
	{"a password in a list of flags", []string{"JAVA_OPTS", "MYSQL_OPTS", "CATALINA_OPTS", "MAVEN_OPTS"},
		random(func(g gen) string { return fmt.Sprintf(g.oneOf(flagLists...), g.chosen()) }), assigned},
	{"a password a flag sets as NAME=value", []string{"DOCKER_RUN_OPTS", "HELM_ARGS", "TF_CLI_ARGS_apply", "ANSIBLE_ARGS", "SPARK_SUBMIT_OPTS"},
		random(func(g gen) string { return fmt.Sprintf(g.oneOf(keyedFlags...), g.chosen()) }), assigned},
	{"a login attached to a flag", []string{"CURL_OPTS", "REDIS_CLI_OPTS", "SMB_OPTS", "PROXY_OPTS"},
		random(func(g gen) string {
			form, password := g.oneOf(attachedLogins...), g.login()
			// A PIN after -P looks exactly like mysql's port, so it is left out.
			if strings.Contains(form, "-P%s") {
				password = g.chosen()
			}
			return fmt.Sprintf(form, g.oneOf("alice", "svc-ledger", "deploy"), password)
		}), assigned},
	{"a mysql password holding =", []string{"MYSQL_OPTS", "MYSQL_ARGS", "DB_CLI_OPTS"},
		random(func(g gen) string { return "-uadmin -p" + g.withEquals() + " -hdb.internal" }), assigned},
	// Generators capitalise words and add digits, with nothing to split the token.
	{"a passphrase in CamelCase", []string{"WIFI_PHRASE", "VPN_PHRASE", "NAS_UNLOCK", "ROOT_PASSWORD"},
		func(g gen) string { return g.camelPhrase(false) }, []recallForm{commentedOut, bare, note, trailer}},
	{"a passphrase in CamelCase with a word such as I, A, OK, TV or USA", []string{"WIFI_PHRASE", "VPN_PHRASE", "NAS_UNLOCK", "ROOT_PASSWORD"},
		func(g gen) string { return g.camelPhrase(true) }, []recallForm{commentedOut, bare, note, trailer}},
	{"a token beside a link to a document", []string{"RUNBOOK_LINKS", "DOC_LINKS"},
		func(g gen) string { return g.besideDocument(g.document(), g.mixed(g.between(24, 32))) }, []recallForm{commentedOut, bare, note, trailer}},
	// origin/main listed one of one case and digits only for the document's ID.
	{"a token of one case and digits beside a document's ID", []string{"RUNBOOK_LINKS", "DOC_LINKS"},
		func(g gen) string { return g.besideDocument(g.keyedDocument(), g.oneCase(g.between(30, 40))) }, []recallForm{commentedOut, bare, note, trailer}},
	// A known prefix is part of the value, so a label names its kind instead.
	{"a GitHub token", []string{"GITHUB_TOKEN", "GH_PAT", "RELEASE_BOT"},
		func(g gen) string { return "ghp_" + g.mixed(36) }, alsoCommented},
	{"a Stripe secret key", []string{"STRIPE_SECRET_KEY", "BILLING"},
		func(g gen) string { return "sk_" + "live_" + g.mixed(24) }, alsoCommented},
	{"a URL with a generic password and a real API key", []string{"SERVICE_URL", "BILLING_API_URL"},
		func(g gen) string {
			return "https://app:" + g.oneOf("changeme", "admin", "letmein", "default") + "@api.internal/v1?api_key=" + g.mixed(32)
		}, alsoCommented},
}

// perShape fake secrets of each shape are written in each of its forms.
const perShape = 100

// doctor lists every fake secret of a shape origin/main listed, sure or possible,
// and no label it prints holds four characters of the value in a row.
func TestDoctorStillListsEveryShapeOfSecretItListed(t *testing.T) {
	g := gen{rand.New(rand.NewPCG(20251107, 13))}
	dir := t.TempDir()
	files := map[string]*strings.Builder{".zshrc": {}, ".env": {}}
	lines := map[string]int{}
	type placed struct {
		shape, form, value string
	}
	at := map[string]placed{}
	for _, s := range recallShapes {
		for i := range perShape {
			value, name := s.value(g), s.names[i%len(s.names)]
			for _, f := range s.forms {
				b := files[f.file]
				lines[f.file]++
				at[fmt.Sprintf("%s:%d", filepath.Join(dir, f.file), lines[f.file])] = placed{s.what, f.what, value}
				fmt.Fprintf(b, f.line+"\n", name, value)
				// Three blank lines keep each line out of a range of nearby lines.
				b.WriteString("\n\n\n")
				lines[f.file] += 3
			}
		}
	}
	var paths []string
	for name, b := range files {
		paths = append(paths, write(t, dir, name, b.String()))
	}

	r, err := doctor.Run(vault.NewMemory(), paths, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// holder names what holds each line listed, which its row shows before its label.
	holder := map[string]string{}
	for _, p := range r.Plaintext {
		holder[fmt.Sprintf("%s:%d", p.File, p.Line)] = p.Name
	}
	for _, u := range r.Unmovable {
		holder[fmt.Sprintf("%s:%d", u.File, u.Line)] = u.Kind
	}
	missed := map[string]int{}
	for where, p := range at {
		if holder[where] == "" {
			missed[p.shape+", as "+p.form]++
		}
	}
	for what, n := range missed {
		t.Errorf("%d of %d fake secrets are not listed: %s", n, perShape, what)
	}

	// Rows by where they are, read once: finding each in the whole report took
	// minutes under the race detector.
	byPlace := map[string]string{}
	for _, got := range rows(r.Render(doctor.Format{})) {
		if where, _, _ := strings.Cut(got, " "); byPlace[where] == "" {
			byPlace[where] = got
		}
	}
	// Each entry's label follows its tag and what holds it.
	labelled := 0
	for where, holds := range holder {
		_, label, ok := strings.Cut(byPlace[where]+" ", " "+holds+" ")
		if p, placed := at[where]; ok && placed {
			labelled++
			if sharesFour(p.value, label) {
				t.Errorf("the label for %s, as %s, holds part of its value", p.shape, p.form)
			}
		}
	}
	if labelled != len(holder) {
		t.Errorf("read the labels of %d entries, want one for each of the %d lines listed", labelled, len(holder))
	}
}

// sharesFour reports whether a and b have four characters in a row in common.
func sharesFour(a, b string) bool {
	for i := 0; i+4 <= len(a); i++ {
		if strings.Contains(b, a[i:i+4]) {
			return true
		}
	}
	return false
}

// classes counts which of upper case, lower case and digits s holds.
func classes(s string) int {
	n := 0
	for _, set := range []string{upperLetters, lowerLetters, digitChars} {
		if strings.ContainsAny(s, set) {
			n++
		}
	}
	return n
}
