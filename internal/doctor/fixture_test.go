package doctor_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/veilux-lab/keyward/internal/doctor"
	"github.com/veilux-lab/keyward/internal/mcpconfig"
)

// Fake hashes and keys for the fixture. Each one shaped like a provider's key is
// split, so secret scanners do not report it.
const (
	sha256Hex  = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	commitHex  = "3f9a2b7c1d8e4f6a0b5c9d2e7f1a4b8c3d6e9f02"
	sriSHA512  = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
	fakeUUID   = "3f2a9c1e-7b4d-4e8f-9a6b-" + "2c1d0e5f7a8b"
	headerKey  = "Ab3dEf6hIj9lMn2pQr5tUv8x"
	awsKeyID   = "AKIA" + "IOSFODNN7EXAMPLE"
	shortToken = "Kq7pL2xV9mN4"
)

// A verdict is what doctor should make of a line.
type verdict int

const (
	// leftOut is a setting a rule recognises, which doctor does not list.
	leftOut verdict = iota
	// neverSure may be listed, but never as a credential of a known shape.
	neverSure
	// stillListed is a setting no rule recognises yet, which doctor lists.
	stillListed
	// credential is a secret, which doctor lists.
	credential
	// knownGap is a secret that looks exactly like a setting a rule recognises, so
	// doctor does not list it.
	knownGap
)

// fixture is realistic rc lines with fake values.
var fixture = []struct {
	what    string
	line    string
	verdict verdict
}{
	{"an editor", "export EDITOR=nvim", leftOut},
	{"a locale", "export LANG=en_US.UTF-8", leftOut},
	{"an AWS profile", "export AWS_PROFILE=payments-dev", leftOut},
	{"a PATH", `export PATH="/opt/homebrew/bin:$PATH"`, leftOut},
	{"a heading", "# Load nvm, pyenv and rbenv for local development", leftOut},
	{"an ECR registry host", "export AWS_ECR_URI=123456789012.dkr.ecr.us-west-2.amazonaws.com", leftOut},
	{"an ECR repository", "export ECR_REPOSITORY=123456789012.dkr.ecr.us-west-2.amazonaws.com/payments/api", leftOut},
	{"an RDS host and port", "export RDS_ENDPOINT=payments-prod.c9akciq32xyz.us-east-1.rds.amazonaws.com:5432", leftOut},
	{"compiler flags", `export CPPFLAGS="-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/readline/include"`, leftOut},
	{"linker flags", `export LDFLAGS="-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/readline/lib"`, leftOut},
	{"commented-out compiler flags", `# export CPPFLAGS="-I/opt/homebrew/opt/libpq/include -I/opt/homebrew/opt/openssl@3/include"`, leftOut},
	{"Java options", `export JAVA_OPTS="-Xmx2g -XX:+UseG1GC -Dspring.profiles.active=dev -Dfile.encoding=UTF-8"`, leftOut},
	{"Maven options", `export MAVEN_OPTS="-Xms512m -Xmx2g -XX:MaxMetaspaceSize=512m"`, leftOut},
	{"Gradle options", `export GRADLE_OPTS="-Dorg.gradle.daemon=false -Dorg.gradle.jvmargs=-Xmx4g"`, leftOut},
	{"Node options", `export NODE_OPTIONS="--max-old-space-size=8192 --enable-source-maps"`, leftOut},
	{"Kafka's brokers", "export KAFKA_BROKERS=b-1.payments.kafka.us-west-2.amazonaws.com:9094,b-2.payments.kafka.us-west-2.amazonaws.com:9094", leftOut},
	{"bootstrap servers", "export BOOTSTRAP_SERVERS=localhost:9092,kafka-1.internal:9092,kafka-2.internal:9093", leftOut},
	{"an IAM role's ARN", "export ROLE_ARN=arn:aws:iam::123456789012:role/OrganizationAccountAccessRole", leftOut},
	{"an EKS cluster's ARN", "export EKS_CLUSTER=arn:aws:eks:us-west-2:123456789012:cluster/payments-prod", leftOut},
	{"an image pinned by digest", "export BASE_IMAGE=ghcr.io/example/payments-api@sha256:" + sha256Hex, leftOut},
	{"an image's digest", "export IMAGE_DIGEST=sha256:" + sha256Hex, leftOut},
	{"a package's integrity", "export LOCKFILE_INTEGRITY=" + sriSHA512, leftOut},
	{"a host key's fingerprint", "export SSH_HOST_FINGERPRINT=SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU", leftOut},
	{"an archive's checksum", "export ARCHIVE_CHECKSUM=q3Vt8ZkYp1Lr0Xw9NcEa6HbJd2Ms5Ug7Fi4Ko+Ty/8E=", leftOut},
	{"a commit hash", "export GIT_COMMIT_SHA=" + commitHex, leftOut},
	{"a digest in a comment", "# pinned to nginx@sha256:" + sha256Hex, leftOut},
	{"a commit link", "# https://github.com/example-org/payments/commit/" + commitHex, leftOut},
	{"a file link at a commit", "# https://github.com/example-org/payments/blob/" + commitHex + "/deploy.sh", leftOut},
	{"a Google Doc", "# see https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/edit", leftOut},
	{"a Drive folder", "# https://drive.google.com/drive/folders/1AbCdEfGhIjKlMnOpQrStUvWxYz012345", leftOut},
	{"a Notion page", "# runbook https://www.notion.so/example/Payments-Runbook-" + hex32, leftOut},
	{"a gist", "# https://gist.github.com/someone/" + hex32, leftOut},
	{"a Loom video", "# demo https://www.loom.com/share/" + hex32, leftOut},
	{"a Figma file", "# design https://www.figma.com/design/AbCdEf1234GhIjKl5678MnOpQr/Checkout", leftOut},
	{"CamelCase classes in a comment", "# Client: OAuth2AuthorizedClientManager and ReactiveOAuth2AuthorizedClientManager", leftOut},
	{"more CamelCase classes", "# Spring Security: OAuth2TokenRelayGatewayFilterFactory, ReactiveOAuth2CredentialsProviderManager", leftOut},
	{"a GitHub token placeholder", "export GITHUB_TOKEN=" + "ghp_" + strings.Repeat("x", 36), leftOut},
	{"a Stripe test key placeholder", "export STRIPE_SECRET_KEY=" + "sk_test_" + strings.Repeat("x", 24), leftOut},
	{"an AWS key ID placeholder", "export AWS_ACCESS_KEY_ID=" + "AKIA" + strings.Repeat("X", 16), leftOut},
	{"a template", `export OPENAI_API_KEY="<your-openai-api-key>"`, leftOut},
	{"a URL with a template for its password", "export ANALYTICS_DB_URL=postgres://app:<password>@db.internal:5432/analytics", leftOut},
	{"a commented-out Slack placeholder", "# export SLACK_BOT_TOKEN=" + "xoxb-" + strings.Repeat("x", 24), leftOut},

	// Neither a login nor a key, though each has an @ or a / where one would.
	{"a Kerberos principal", "export KRB5_PRINCIPAL=HTTP/web01.example.com@EXAMPLE.COM", neverSure},
	{"a Kerberos service principal", "export PG_PRINCIPAL=postgres/db01.payments.example.com@PAYMENTS.EXAMPLE.COM", neverSure},
	{"a GCP service account member", "export DEPLOYER=serviceAccount:deployer@my-project-123456.iam.gserviceaccount.com", neverSure},
	{"a GCP user member", "export OWNER_MEMBER=user:alice@example.com", neverSure},
	{"a GCP group member", "export ADMINS_MEMBER=group:platform-admins@example.com", neverSure},
	{"a release asset", "export RELEASE_ASSET=releases/app@v2.1.0.zip", neverSure},
	{"a GitHub action", "export CHECKOUT_ACTION=actions/checkout@v4.1.1", neverSure},
	{"an npm package", "export LSP_PACKAGE=npm:typescript-language-server@4.3.3", neverSure},
	{"a Homebrew keg", "export OPENSSL_KEG=homebrew/openssl@3", neverSure},
	{"a member in a comment", "# owner: user:alice@example.com", neverSure},
	{"a principal in a comment", "# principal HTTP/web01.example.com@EXAMPLE.COM", neverSure},

	// No rule recognises these yet.
	{"an OTEL header list with no key", `export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-dataset=checkout-service,x-honeycomb-environment=production"`, stillListed},
	{"a JSON list of services", `export MCP_SERVICES='["github","linear","notion","slack","atlassian","pagerduty"]'`, stillListed},
	{"one compiler flag", "export SDK_CPPFLAGS=-I/Library/Developer/CommandLineTools/SDKs/MacOSX14.sdk/usr/include", stillListed},
	{"hosts beside addresses", "export NO_PROXY=localhost,127.0.0.1,.internal.example.com,169.254.169.254,.svc.cluster.local", stillListed},
	{"an Elasticsearch host", "export ES_ENDPOINT=search-logs-abc123def456ghi789jkl0mnop.us-west-2.es.amazonaws.com", stillListed},
	{"a CamelCase class in a value", "export SPRING_CLIENT_CLASS=com.example.billing.OAuth2AuthorizedClientManagerConfig", stillListed},
	{"a commit after the word", "# commit " + commitHex + " fixed the deploy script", stillListed},
	{"an ETag that is no digest", `export BUNDLE_ETAG='W/"0815-Zx9kQm2vLp7wRt4yNb8cFj1h"'`, stillListed},
	{"a your-...-here placeholder", "export LINEAR_API_KEY=your-linear-api-key-here", stillListed},
	{"a changeme placeholder", "export DB_PASSWORD=changeme-before-prod", stillListed},
	{"a URL with a generic password", "export DATABASE_URL=postgres://app:password@localhost:5432/app", stillListed},

	{"a GitHub token", "export GITHUB_TOKEN=" + "ghp_" + "FakeFixtureToken00000000000000000000", credential},
	{"an OpenAI key", "export OPENAI_API_KEY=" + "sk-proj-" + "FakeFixtureOpenAIKey0000000000000000", credential},
	{"a Slack token", "export SLACK_BOT_TOKEN=" + "xoxb-" + "123456789012-1234567890123-FakeFixtureSlack00", credential},
	{"AWS's example key pair", "export AWS_ACCESS_KEY_ID=" + awsKeyID, credential},
	{"AWS's example secret key", "export AWS_SECRET_ACCESS_KEY=" + awsSecretKey, credential},
	{"a Stripe key", "export STRIPE_SECRET_KEY=" + "sk_live_" + "FakeFixtureStripeKey0000", credential},
	{"a JWT", "export ID_JWT=" + "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl", credential},
	{"base64-encoded JSON", "export SPLUNK_MCP_TOKEN=eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9", credential},
	{"a hex key under a credential's name", "export DATADOG_API_KEY=" + hex32, credential},
	{"a UUID key under a credential's name", "export SEGMENT_WRITE_KEY=" + fakeUUID, credential},
	{"a mixed-case token", "export SERVICE_ID=" + mixedToken, credential},
	{"a lowercase-and-digit token", "export CI_JOB_SEED=a8f3k2m9x7q1w5e4r6t0y2u8i9o7p6", credential},
	{"a symbol password", "export DB_CONN_STRING='Xk9#mZ2!vLp7@wRt4%yNb8&cFj1^qD'", credential},
	{"a header list holding a key", `export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=` + headerKey + `,x-honeycomb-dataset=checkout"`, credential},
	{"a header list holding a short key", `export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=` + shortToken + `,x-honeycomb-dataset=checkout"`, credential},
	{"a MySQL DSN", "export MYSQL_DSN='app:Pa55w0rd" + shortToken + "@tcp(db.internal:3306)/payments'", credential},
	{"a Kafka login", "export KAFKA_SASL=svc-orders:" + shortToken + "@kafka.internal:9092", credential},
	{"a pgpass line", "export PGPASS_LINE=ledger-db.internal:5432:ledger:ledger_app:Wd7kQ2mX9vLpRt", credential},
	{"an Oracle thin URL", "export ORACLE_URL=jdbc:oracle:thin:ledger_app/" + shortToken + "@ledger-db.internal:1521/LEDGERPDB", credential},
	{"a key under a digest's name", "export LEDGER_HMAC_SHA256=q3Vt8ZkYp1Lr0Xw9NcEa6HbJd2Ms5Ug7Fi4Ko+Ty/8E=", credential},
	{"a flag holding a key", `export SENTRY_CFLAGS="-DSENTRY_KEY=` + hex32 + ` -O2"`, credential},
	{"a password in Java options", `export JAVA_TOOL_OPTIONS="-Xmx2g -Djavax.net.ssl.keyStorePassword=Tr0ub4dor3xyz"`, credential},
	{"a passphrase separated by dots", "export NAS_LOGIN='thistle.fjord.meadow.quartz.maple'", credential},
	{"a webhook with no scheme", "export INGEST_ENDPOINT=hooks.internal.example.com/ingest/j7tvztuz595epecir0x", credential},
	{"a Pipedream endpoint", "export PIPEDREAM_HOST=eo2fo7ycxmc1x0p.m.pipedream.net", credential},
	{"a database URL", "export DATABASE_URL=postgresql://app:S3cr3tP4ss@db.internal:5432/payments", credential},
	{"a URL with a template and a real key", "export BILLING_URL='postgres://app:<password>@db.internal:5432/billing?api_key=" + mixedToken + "'", credential},
	{"an old token in a comment", "# old: " + "ghp_" + "FakeFixtureOldToken00000000000000000", credential},
	{"a commented-out database URL", "# export DATABASE_URL=postgresql://app:S3cr3tP4ss@db.internal:5432/payments", credential},
	{"a commented-out symbol password", "# export DB_CONN='Xk9#mZ2!vLp7@wRt4%yNb8&cFj1^qD'", credential},
	{"a token in an alias", "alias deploy='DEPLOY_TOKEN=" + mixedToken + " ./deploy.sh'", credential},
	{"a token beside a reference", "export A='cap://alpha' # was " + "ghp_" + "FakeFixtureWasToken00000000000000000", credential},
	{"an AWS key pair in a comment", "# " + awsKeyID + " " + awsSecretKey, credential},
	{"hex in a comment", "# " + hex32, credential},
	{"a token in an MCP endpoint's path", "# https://mcp.example.com/" + headerKey + "/mcp", credential},
	{"a token in a document link's query", "# https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/export?access_token=" + mixedToken, credential},
	{"a passphrase in CamelCase", "# vpn password: CorrectHorseBatteryStaple1", credential},
	{"a passphrase in CamelCase after a plain word", "# wifi is PurpleMonkeyDishwasher42", credential},
	{"a token set with launchctl", "launchctl setenv NPM_TOKEN " + "npm_" + "FakeFixtureLaunchctl0000000000000000", credential},

	// Known gaps, which look exactly like host names: a passphrase of words joined
	// by dots whose last word is a suffix hosts use, such as local, corp, net, dev
	// or svc, and a capability URL's token made only of letters.
	{"a passphrase separated by dots ending in local", "export WIFI_PHRASE='thistle.fjord.meadow.quartz.local'", knownGap},
	{"a webhook whose token is letters alone", "export INGEST_ENDPOINT=hooks.internal.example.com/ingest/qwhzkcmrtxbvplnf", knownGap},
	{"a Pipedream endpoint whose token is letters alone", "export PIPEDREAM_HOST=eoqwhzkcmrtxbvpl.m.pipedream.net", knownGap},
}

// fixtureServers are an MCP server's env, judged as the fixture's lines are.
var fixtureServers = []struct {
	key, value string
	verdict    verdict
}{
	{"AWS_ECR_URI", "123456789012.dkr.ecr.us-west-2.amazonaws.com", leftOut},
	{"JAVA_TOOL_OPTIONS", "-Xmx2g -XX:+UseG1GC -Dfile.encoding=UTF-8", leftOut},
	{"LINEAR_API_KEY", "<your-linear-api-key>", leftOut},
	{"IMAGE_DIGEST", "sha256:" + sha256Hex, leftOut},
	{"MCP_SERVICES", `["github","linear","notion","slack","atlassian","pagerduty"]`, stillListed},
	{"DD_API_KEY", hex32, credential},
	{"JAVA_OPTS", "-Xmx1g -Dspring.datasource.password=Tr0ub4dor3xyz", credential},
	{"NAS_LOGIN", "thistle.fjord.meadow.quartz.maple", credential},
	{"HONEYCOMB_HEADERS", "x-honeycomb-team=" + headerKey + ",x-honeycomb-dataset=checkout", credential},
}

// doctor's verdicts on the fixture are what keep a long rc file's report short
// enough to act on, while every secret but a known gap is still listed.
func TestDoctorJudgesRealisticLines(t *testing.T) {
	var content strings.Builder
	for _, f := range fixture {
		content.WriteString(f.line + "\n")
	}
	rc := write(t, t.TempDir(), ".zshrc", content.String())
	env := map[string]string{}
	for _, s := range fixtureServers {
		env[s.key] = s.value
	}
	servers := []mcpconfig.Server{{Client: "Claude Code", Config: "/home/someone/.claude.json", Name: "fixture", Command: "fixture-mcp", Env: env}}

	r, err := doctor.Run(store(t, map[string]string{"alpha": ""}), []string{rc}, servers)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	listed, sure := map[string]bool{}, map[string]bool{}
	for _, p := range r.Plaintext {
		where := fmt.Sprint(p.Line)
		listed[where], sure[where] = true, sure[where] || p.KnownShape
	}
	for _, u := range r.Unmovable {
		where := fmt.Sprint(u.Line)
		listed[where], sure[where] = true, sure[where] || u.KnownShape
	}
	for _, l := range r.Literals {
		listed[l.Field], sure[l.Field] = true, sure[l.Field] || l.KnownShape
	}
	var others, alarms, sureAlarms, secrets, missed int
	judge := func(what, where string, v verdict) {
		secret := v == credential || v == knownGap
		if secret {
			secrets++
		} else {
			others++
		}
		if listed[where] && !secret {
			alarms++
		}
		if sure[where] && !secret {
			sureAlarms++
		}
		switch {
		case v == credential && !listed[where]:
			missed++
			t.Errorf("%s, %s, is not listed", where, what)
		case v == knownGap && listed[where]:
			t.Errorf("%s, %s, is listed now: make it credential", where, what)
		case v == knownGap:
			missed++
		case v == leftOut && listed[where]:
			t.Errorf("%s, %s, is listed (sure: %v)", where, what, sure[where])
		case v == neverSure && sure[where]:
			t.Errorf("%s, %s, is listed as a credential of a known shape", where, what)
		case v == stillListed && !listed[where]:
			t.Errorf("%s, %s, is no longer listed: make it leftOut", where, what)
		}
	}
	for i, f := range fixture {
		judge(f.what, fmt.Sprint(i+1), f.verdict)
	}
	for _, s := range fixtureServers {
		judge(s.key, "env."+s.key, s.verdict)
	}
	t.Logf("%d of %d other lines listed (%d as sure), %d of %d secrets missed", alarms, others, sureAlarms, missed, secrets)

	// No piece of a line that could be a value is printed, though the name of a
	// variable listed is.
	out, shown := r.String(), map[string]bool{}
	for _, p := range r.Plaintext {
		shown[p.Name] = true
	}
	for _, f := range fixture {
		for _, piece := range strings.FieldsFunc(f.line, func(c rune) bool { return strings.ContainsRune(" \t'\"=,", c) }) {
			if len(piece) >= 12 && strings.ContainsAny(piece, "0123456789") && !shown[piece] && strings.Contains(out, piece) {
				t.Errorf("the report printed part of %s", f.what)
			}
		}
	}
}
