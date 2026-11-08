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
		// Split so secret scanners do not report these fake tokens.
		{"SLACK_BOT_TOKEN", "xoxb-" + "123456789012-1234567890123-AbCdEfGhIjKlMnOp"},
		{"GITLAB_TOKEN", "glpat-AbCdEfGhIjKlMnOpQrSt"},
		{"STRIPE_SECRET", "sk_live_" + "AbCdEfGhIjKlMnOpQrStUvWx"},
		{"GOOGLE_API_KEY", "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz01234567"},
		{"VAULT_TOKEN", "hvs.AbCdEfGhIjKlMnOpQrStUvWxYz"},
		{"NPM_TOKEN", "npm_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"},
		{"SIGNING_KEY", "-----BEGIN RSA PRIVATE KEY-----"},
		{"DB_PASSWORD", "correct-horse-battery-staple-9271"},
		// Short forms of password, matched as whole words of the name.
		{"ACCOUNTS_DB_PW", "correct-horse-battery-staple-9271"},
		{"DEV_DB_PASS", "correct-horse-battery-staple-9271"},
		{"DB_PWD", "correct-horse-battery-staple-9271"},
		{"GPG_PASSPHRASE", "correct-horse-battery-staple-9271"},
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
		// PASS and PW only count as whole words of the name.
		{"BYPASS_PROXY_HOSTS", "localhost,127.0.0.1,internal"},
		{"PASSENGER_LIMIT", "approximately-forty-two"},
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

// A digest is random by design but no secret: one written whole with its
// algorithm, an image pinned by one, or one shaped as a digest is under a name
// that says it is one, unless the name also has a word for a credential, as a
// key's can.
func TestDetectDigestsAreNeverRandom(t *testing.T) {
	const sha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, c := range []struct{ name, value string }{
		{"LOCKFILE", "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="},
		{"SRI", "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"},
		{"KNOWN_HOST", "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"},
		{"LAYER", "sha256:" + sha256Hex},
		{"BASE_IMAGE", "ghcr.io/example/payments-api@sha256:" + sha256Hex},
		{"PROXY_IMAGE", "nginx:1.25@sha256:" + sha256Hex},
		{"SSH_HOST_FINGERPRINT", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"},
		{"TARBALL_SHA256", sha256Hex},
		{"GIT_COMMIT_SHA", sha256Hex[:40]},
		{"S3_OBJECT_ETAG", sha256Hex[:32]},
		{"ARCHIVE_CHECKSUM", "q3Vt8ZkYp1Lr0Xw9NcEa6HbJd2Ms5Ug7Fi4Ko+Ty/8E="},
		{"PACKAGE_INTEGRITY", "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="},
	} {
		got := migrate.Detect(c.name, c.value)
		if got.Possible || got.Secret || got.Reason == "" {
			t.Errorf("Detect(%q, %q) = %+v, want no verdict, with a reason", c.name, c.value, got)
		}
	}
	for _, c := range []struct{ name, value string }{
		{"LEDGER_HMAC_SHA256", "q3Vt8ZkYp1Lr0Xw9NcEa6HbJd2Ms5Ug7Fi4Ko+Ty/8E="},
		{"PAYLOAD_SIGNING_DIGEST", "q3Vt8ZkYp1Lr0Xw9NcEa6HbJd2Ms5Ug7Fi4Ko+Ty/8E="},
		// Not a digest's length, or more than a digest.
		{"KNOWN_HOST", "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuF"},
		{"LAYER", "sha256:" + sha256Hex + ":Zx9kQm2vLp7wRt4yNb8cFj1h"},
		// A random token beside a digest is judged as any is.
		{"BASE_IMAGE", "ghcr.io/zx9kqm2vlp7wrt4ynb8cfj1hgd5sae3u/api@sha256:" + sha256Hex},
		// A name only says what a value of a digest's shape is. A token of letters
		// and digits alone is not base64 of one, though it can decode to a digest's
		// length, as 43 characters ending in A and any 64 do.
		{"BACKUP_HASH", "PI6YwTrTJvxQb3J3RHdr2sYElxeSSQ29nk"},
		{"ASSET_HASH", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i"},
		{"RELEASE_SHA", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i"},
		{"RELEASE_SHA", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6iKq7pL2A"},
		{"ASSET_DIGEST", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6iKq7pL2xV9mN4wRt5Ab3dEf6hIj9l"},
		{"BUNDLE_ETAG", `W/"0815-Zx9kQm2vLp7wRt4yNb8cFj1h"`},
	} {
		if got := migrate.Detect(c.name, c.value); !got.Possible {
			t.Errorf("Detect(%q, %q).Possible = false, want it flagged (reason: %s)", c.name, c.value, got.Reason)
		}
	}
}

// A host name, a registry URI and an ARN can look random as a whole, but each is
// made of names, so one with no random token in it is not flagged.
func TestDetectHostNamesAndARNsAreNotRandom(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"AWS_ECR_URI", "123456789012.dkr.ecr.us-west-2.amazonaws.com"},
		{"ECR_REPOSITORY", "123456789012.dkr.ecr.us-west-2.amazonaws.com/payments/api"},
		{"RDS_HOST", "payments-prod.c9akciq32xyz.us-east-1.rds.amazonaws.com:5432"},
		{"ECR_CHINA", "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn/payments/api"},
		{"ROLE_ARN", "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"},
		{"EKS_CLUSTER", "arn:aws:eks:us-west-2:123456789012:cluster/payments-prod"},
	} {
		got := migrate.Detect(c.name, c.value)
		if got.Possible || got.Secret || got.Reason == "" {
			t.Errorf("Detect(%q, %q) = %+v, want no verdict, with a reason", c.name, c.value, got)
		}
	}
	for _, c := range []struct{ name, value string }{
		// A label or a resource can hold a random token, a UUID among them.
		{"ES_ENDPOINT", "search-logs-abc123def456ghi789jkl0mnop.us-west-2.es.amazonaws.com"},
		{"SOPS_KMS_ARN", "arn:aws:kms:us-west-2:123456789012:key/3f2a9c1e-7b4d-4e8f-9a6b-2c1d0e5f7a8b"},
		// Capitals, a query, and more after the host are no host name's.
		{"ENDPOINT", "Zx9kQm2vLp7wRt4y.example.com"},
		{"REGISTRY", "123456789012.dkr.ecr.us-west-2.amazonaws.com?token=abcdef"},
		{"LOGIN", "svc-orders:Kq7pL2xV9mN4@kafka.internal:9092"},
		// Words joined by dots, as a passphrase can be, end in no suffix hosts use.
		{"NAS_LOGIN", "thistle.fjord.meadow.quartz.maple"},
		// A capability URL's token is longer than a host's own ID, in a label or the
		// path, or the host is no name a host uses.
		{"NTFY_TOPIC_URL", "ntfy.sh/9s0s2mcvkjxrk95a4"},
		{"PIPEDREAM_HOST", "eo2fo7ycxmc1x0p.m.pipedream.net"},
		{"INGEST_ENDPOINT", "hooks.internal.example.com/ingest/j7tvztuz595epecir0x"},
		{"INGEST_ENDPOINT", "hooks.internal.example.com/ingest/a3f9c2e17b4d8f60e5a1c9b2"},
		{"INGEST_ENDPOINT", "hooks.internal.example.com/ingest/k3j9x2m1"},
	} {
		if got := migrate.Detect(c.name, c.value); !got.Possible {
			t.Errorf("Detect(%q, %q).Possible = false, want it flagged (reason: %s)", c.name, c.value, got.Reason)
		}
	}
}

// A list of host names, registry URIs and ARNs, as Kafka's brokers are written, is
// made of names too, however it separates them.
func TestDetectListsOfHostNamesAreNotRandom(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"KAFKA_BROKERS", "b-1.payments.kafka.us-west-2.amazonaws.com:9094,b-2.payments.kafka.us-west-2.amazonaws.com:9094"},
		{"BOOTSTRAP_SERVERS", "localhost:9092,kafka-1.internal:9092,kafka-2.internal:9093"},
		{"REDIS_NODES", "redis-a.cache.internal:6379; redis-b.cache.internal:6379"},
		{"ECR_REPOSITORIES", "123456789012.dkr.ecr.us-west-2.amazonaws.com/payments 123456789012.dkr.ecr.eu-west-1.amazonaws.com/ledger"},
		{"TOPICS", "arn:aws:sns:us-west-2:123456789012:orders arn:aws:sns:us-west-2:123456789012:refunds"},
	} {
		got := migrate.Detect(c.name, c.value)
		if got.Possible || got.Secret || got.Reason == "" {
			t.Errorf("Detect(%q, %q) = %+v, want no verdict, with a reason", c.name, c.value, got)
		}
	}
	for _, c := range []struct{ name, value string }{
		// An address, a domain's suffix, a word, a login and a token are none.
		{"NO_PROXY", "localhost,127.0.0.1,.internal.example.com,169.254.169.254,.svc.cluster.local"},
		{"VPN_PHRASE", "quick brown fox jumps over the lazy dog"},
		{"BROKERS", "b-1.kafka.internal:9094,svc:Kq7pL2xV9mN4@kafka.internal:9092"},
		{"HOSTS", "api.example.com,Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i"},
	} {
		if got := migrate.Detect(c.name, c.value); !got.Possible {
			t.Errorf("Detect(%q, %q).Possible = false, want it flagged (reason: %s)", c.name, c.value, got.Reason)
		}
	}
}

// Compiler, linker and JVM flags can look random as a whole, but two or more of
// them, with no random token in any, are no credential. One alone is judged as any
// value is, as a password can start with a dash.
func TestDetectListsOfFlagsAreNotRandom(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"CPPFLAGS", "-I/opt/homebrew/opt/openssl@3/include -I/opt/homebrew/opt/readline/include"},
		{"CPPFLAGS", "-I/Library/Developer/CommandLineTools/SDKs/MacOSX14.sdk/usr/include -I/opt/homebrew/include"},
		{"LDFLAGS", "-L/opt/homebrew/opt/openssl@3/lib -L/opt/homebrew/opt/readline/lib"},
		{"CFLAGS", "-isystem /opt/homebrew/include -O2 -Wl,-rpath,/opt/homebrew/lib"},
		{"JAVA_OPTS", "-Xmx2g -XX:+UseG1GC -Dspring.profiles.active=dev -Dfile.encoding=UTF-8"},
		{"MAVEN_OPTS", "-Xms512m -Xmx2g -XX:MaxMetaspaceSize=512m"},
		{"NODE_OPTIONS", "--max-old-space-size=8192 --enable-source-maps"},
		{"GRADLE_OPTS", "-Dorg.gradle.daemon=false -Dorg.gradle.jvmargs=-Xmx4g"},
		{"TF_CLI_ARGS_plan", "-parallelism=20 -lock-timeout=300s"},
		{"CFLAGS", "-O2 -pthread -I/opt/homebrew/include"},
		// The JVM's agent flags start as -a<user>:<password> does.
		{"JAVA_TOOL_OPTIONS", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -Xmx2g"},
		{"JAVA_TOOL_OPTIONS", "-Xmx2g -agentpath:/opt/yourkit/bin/libyjpagent.so=port=10001"},
		// A macro's name holds no % or :, and mysql's -P takes a port.
		{"CPPFLAGS", "-UNDEBUG -D_FORTIFY_SOURCE=2 -I/opt/homebrew/include"},
		{"MYSQL_ARGS", "-uadmin -P3306 -hdb.internal.example.com"},
		// No key a flag sets has a word for a credential.
		{"HELM_ARGS", "--atomic --set=image.tag=1.4.2 --set=replicaCount=3 --wait"},
		{"ANSIBLE_ARGS", "--check --extra-vars=env=prod,region=us-west-2"},
	} {
		got := migrate.Detect(c.name, c.value)
		if got.Possible || got.Secret || got.Reason == "" {
			t.Errorf("Detect(%q, %q) = %+v, want no verdict, with a reason", c.name, c.value, got)
		}
	}
	for _, c := range []struct{ name, value string }{
		{"CPPFLAGS", "-I/opt/homebrew/opt/openssl@3/include"},
		{"SENTRY_CFLAGS", "-DSENTRY_KEY=" + "9f8e7d6c5b4a39281706fedcba098765 -O2"},
		{"JAVA_TOOL_OPTIONS", "-Djavax.net.ssl.keyStorePassword=Zx9kQm2vLp7wRt4yNb8cFj1h -Xmx2g"},
		// A word after a flag is no path it takes.
		{"DB_ARGS", "--user admin --password Kq7pL2xV9mN4wR"},
		// A password a person chose looks no more random than a flag does, so a flag
		// that can hold one is judged as any value is: one named for a credential,
		// or setting a key named for one, alone or in a list, mysql's -p<password>,
		// = and all, isql's -P<password>, a login attached to -u, -a or -U, one whose
		// name says user set to a user and a password joined by : or %, or one set
		// to a user and a password.
		{"MYSQL_OPTS", "--user=admin --password=Xk9mP2vL7qR4nT8"},
		{"JAVA_OPTS", "-Xmx2g -Dspring.datasource.password=Xk9mP2vL7qR4nT8"},
		{"CATALINA_OPTS", "-Xms512m -Djavax.net.ssl.keyStorePassword=Xk9mP2vL7qR4nT8"},
		{"JAVA_OPTS", "-Dhttp.proxyUser=alice -Dhttp.proxyPassword=Summer2024x"},
		{"JAVA_OPTS", "-Xmx512m -Ddb.pw=hunter2hunter2x"},
		{"MAVEN_OPTS", "-Xmx1g -Dgpg.passphrase=correct-horse-battery-staple"},
		{"NODE_OPTIONS", "--max-old-space-size=4096 --api-key=Kx7pQ2mV9nL4wR8t"},
		{"MYSQL_ARGS", "-uadmin -pXk9mP2vL7qR4nT8 -hdb.internal"},
		{"MYSQL_ARGS", "-uadmin -psecretpassword -hdb.internal"},
		{"MYSQL_ARGS", "-uadmin -pXk9m=P2vL7qR4nT8 -hdb.internal"},
		{"MYSQL_ARGS", "-uadmin -pg=2ylSmjBvt -hdb.internal"},
		{"MYSQL_ARGS", "-uadmin -pg/2ylSmjBvt9 -hdb.internal"},
		{"MYSQL_ARGS", "-uadmin -pie=2ylSmjBvt -hdb.internal"},
		{"DOCKER_RUN_OPTS", "--rm --env=RABBITMQ_ERLANG_COOKIE=SWQOKODSQALRPCLNMEQG --network=host"},
		{"DOCKER_RUN_OPTS", "--rm -eRELEASE_COOKIE=Summer2024xQ --network=host"},
		{"CURL_OPTS", "--user=alice:Summer2024x --verbose"},
		{"CURL_OPTS", "-ualice:Summer2024x --silent"},
		{"REDIS_CLI_OPTS", "-hredis.internal -aalice:Summer2024x"},
		{"SMB_OPTS", "--user=alice%Summer2024x --workgroup=CORP"},
		{"CURL_OPTS", "--user=alice:73914625 --verbose"},
		{"PROXY_OPTS", "--proxy-user=alice:73914625 --proxy=proxy.internal:3128"},
		{"SMB_OPTS", "-Ualice%Summer2024xQ --workgroup=CORP"},
		{"SMB_OPTS", "-Ualice%73914625 --workgroup=CORP"},
		{"CURL_OPTS", "-Ualice:Summer2024xQ --proxy=proxy.internal:3128 --silent"},
		{"ISQL_OPTS", "-Usa -PSummer2024xQ -SLEDGER"},
		{"LFTP_OPTS", "-ualice,Summer2024xQ --norc"},
		{"DOCKER_RUN_OPTS", "--rm --env=POSTGRES_PASSWORD=Summer2024xQ --network=host"},
		{"DOCKER_BUILD_OPTS", "--pull --build-arg=NPM_TOKEN=Summer2024xQ --no-cache"},
		{"HELM_ARGS", "--atomic --set=postgresql.auth.password=Summer2024xQ --wait"},
		{"HELM_ARGS", "--install --set-string=redis.password=Summer2024xQ --wait"},
		{"TF_CLI_ARGS_apply", "-var=db_password=Summer2024xQ -auto-approve"},
		{"TF_CLI_ARGS_init", "-backend-config=password=Summer2024xQ -reconfigure"},
		{"ANSIBLE_ARGS", "--check --extra-vars=db_password=Summer2024xQ"},
		{"ANSIBLE_ARGS", "--check --extra-vars=env=prod,db_password=Summer2024xQ"},
		{"ANSIBLE_ARGS", `--check --extra-vars "db_password=Summer2024xQ env=prod"`},
		{"SPARK_SUBMIT_OPTS", "--master=yarn --conf=spark.ssl.keyStorePassword=Summer2024xQ"},
	} {
		if got := migrate.Detect(c.name, c.value); !got.Possible {
			t.Errorf("Detect(%q, %q).Possible = false, want it flagged (reason: %s)", c.name, c.value, got.Reason)
		}
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

// Only the value's own form, at a credential's length, makes a verdict certain.
// A name can mislead (AUTH is in GIT_AUTHOR_EMAIL), and so can a word that happens
// to start like a key: sk-SK is a locale, ASIA a region, eyJ any JSON in base64,
// and a PEM block a public key or a certificate. Those prefixes need their own
// kind's shape: an AWS key id's 16 capitals and digits, an OpenAI key's random
// token, a JWT's three parts, a private key's block.
func TestDetectKnownShapeComesFromTheValueAlone(t *testing.T) {
	for _, c := range []struct {
		name, value string
		want        bool
	}{
		{"GITHUB_TOKEN", "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ", true},
		{"ANY_NAME", "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ", true},
		{"AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS_SESSION_KEY_ID", "ASIAIOSFODNN7EXAMPLE", true},
		{"DATABASE_URL", "postgresql://dbuser:s3cretp4ss@db.internal:5432/dashweb", true},
		{"ID_TOKEN", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl", true},
		{"OPENAI_API_KEY", "sk-proj-FakeOpenAIKey000000000000000000", true},
		{"DEEPSEEK_API_KEY", "sk-" + "0123456789abcdef0123456789abcdef", true},
		{"ANTHROPIC_API_KEY", "sk-ant-api03-FakeAnthropicKey00000000", true},
		{"SSH_KEY", "-----BEGIN OPENSSH PRIVATE KEY-----\\nFakeKeyBody0000\\n-----END OPENSSH PRIVATE KEY-----", true},
		{"TLS_KEY", "-----BEGIN RSA PRIVATE KEY-----\\nFakeKeyBody0000\\n-----END RSA PRIVATE KEY-----", true},
		{"DB_PASSWORD", "correct-horse-battery-staple-9271", false},
		{"GIT_AUTHOR_EMAIL", "someone@example.com", false},
		{"MY_THING", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i", false},
		{"LOCALE", "sk-SK", false},
		{"SUPPORTED_LOCALES", "sk-SK,cs-CZ,de-DE,en-US", false},
		{"CLUSTER_NAME", "sk-production-cluster-01", false},
		{"MARKET", "ASIA", false},
		{"DEPLOY_REGIONS", "ASIA,EUROPE,AMERICAS,AFRICA", false},
		{"MARKET", "ASIA_PACIFIC_SOUTHEAST", false},
		// A JWE has five parts. A JWT is measured by its header, as in a comment.
		{"SPLUNK_MCP_TOKEN", "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9", false},
		{"ENCRYPTED", "eyJhbGciOiJSU0EtT0FFUCJ9.a2V5.aXY.Y2lwaGVy.dGFn", false},
		{"ID_TOKEN", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl", false},
		{"JWT_PUBLIC_KEY", "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A-----END PUBLIC KEY-----", false},
		{"CA_CERT", "-----BEGIN CERTIFICATE-----\\nMIIDdzCCAl+gAwIBAgIEAgAAuTANBgkq\\n-----END CERTIFICATE-----", false},
		{"EDITOR", "vim", false},
	} {
		if got := migrate.Detect(c.name, c.value).KnownShape; got != c.want {
			t.Errorf("Detect(%q, %q).KnownShape = %v, want %v", c.name, c.value, got, c.want)
		}
	}
}

// A comment is judged as a value is: a word that only starts like a key is not
// one of a known shape, though it may be a credential.
func TestCommentsNeedAKnownShapeToo(t *testing.T) {
	for line, want := range map[string]bool{
		"# old key: AKIAIOSFODNN7EXAMPLE\n":                              true,
		"# old key: sk-proj-FakeOpenAIKey000000\n":                       true,
		"# cluster: sk-production-cluster-01\n":                          false,
		"# id: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl.\n": true,
		"# claims: eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9\n":           false,
	} {
		u := migrate.Scan([]byte(line)).Unmovable()
		if len(u) != 1 || u[0].KnownShape != want {
			t.Errorf("%q: unmovable = %+v, want one with KnownShape %v", line, u, want)
		}
	}
}

func TestCredentialPrefixPrefersTheLongestMatch(t *testing.T) {
	for value, want := range map[string]string{
		"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx":   "sk-ant-",
		"Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig": "Bearer ",
		"task-runner": "",
	} {
		if got := migrate.CredentialPrefix(value); got != want {
			t.Errorf("CredentialPrefix(%q) = %q, want %q", value, got, want)
		}
	}
}

// The reason is shown to a human deciding whether to approve a rewrite, so it has
// to say something specific rather than restate the verdict.
func TestDetectReasonsAreSpecific(t *testing.T) {
	cases := []struct {
		name, value, wantSubstring string
	}{
		// A known prefix is part of the value, so the reason names its kind.
		{"GITHUB_TOKEN", "ghp_1a2B3c4D5e6F7g8H9i0JkLmNoPqRs", "a GitHub token"},
		{"SPLUNK_MCP_TOKEN", "eyJraWQiOiJzcGx1bmsiLCJhbGciOiJIUzI1NiJ9", "base64-encoded JSON"},
		{"DB_PASSWORD", "correct-horse-battery-staple-9271", "name"},
		{"MY_THING", "Zx9kQm2vLp7wRt4yNb8cFj1hGd5sAe3uYo6i", "a random 36-character token"},
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
