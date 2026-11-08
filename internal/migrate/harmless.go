package migrate

import (
	"encoding/base64"
	"maps"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// harmless says why a value that looks random as a whole is no credential, or is
// "" if nothing does. Only the whole value fitting the strict form of a digest,
// under a digest's name or with its algorithm, a host name, an ARN or a list of
// them, or a list of flags, with no random token beside it, says so.
func harmless(name, value string) string {
	switch {
	case namesDigest(name) && digestShaped(value):
		return "the name says the value is a digest"
	case isDigest(value):
		return "the value is a digest"
	case isPinnedImage(value):
		return "the value is an image pinned by its digest"
	case isHost(value):
		return "the value is a host name"
	case isARN(value):
		return "the value is an AWS ARN"
	case isHostList(value):
		return "the value is a list of host names"
	case isFlagList(value):
		return "the value is a list of flags"
	}
	return ""
}

// hostName matches a host name of lowercase labels ending in a suffix hosts use,
// or localhost, perhaps with a port and a path of lowercase segments, as a registry
// URI such as 123456789012.dkr.ecr.us-west-2.amazonaws.com/repo is written. Words
// joined by dots that end in another word can be a passphrase. One whose last word
// is such a suffix, as local, corp, net, dev or svc are, looks exactly like a host
// name, so it is not listed: a gap accepted to leave host names out.
var hostName = regexp.MustCompile(`^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:com|net|org|io|dev|aws|cn|internal|local|lan|corp|arpa|svc))(?::[0-9]{1,5})?(?:/[a-z0-9._-]+)*$`)

// isHost reports whether value is a host name, as hostName matches one, with no
// random token in it, as an ID in a label can be, and no capability URL's token.
// A capability URL's token made only of letters looks exactly like a label or a
// path's segment, so it is not listed either.
func isHost(value string) bool {
	host, path, _ := strings.Cut(value, "/")
	return hostName.MatchString(value) && !holdsRandomToken(value) && !holdsID(host, minLabelID) && !holdsID(path, minPathID)
}

// A capability URL's token, as a webhook's or a Pipedream endpoint's is, is an ID
// of minLabelID or more in a label, longer than an RDS host's 12 characters or
// CloudFront's 14, or of minPathID or more in a path, which a repository's or a
// database's name is not.
const (
	minLabelID = 15
	minPathID  = 8
)

// holdsID reports whether s holds n or more letters and digits in a row, mixing
// both, as an ID does.
func holdsID(s string, n int) bool {
	return slices.ContainsFunc(runs(s, isAlnum), func(r []int) bool {
		id := s[r[0]:r[1]]
		return len(id) >= n && strings.ContainsAny(id, "0123456789") && strings.Trim(id, "0123456789") != ""
	})
}

// arn matches an AWS ARN: arn, a partition, a service, a region and an account,
// each perhaps empty as the service has them, and a resource.
var arn = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:[a-z0-9-]+:[a-z0-9-]*:(?:[0-9]{12})?:[A-Za-z0-9_./:+=,@*-]+$`)

// isARN reports whether value is an AWS ARN whose resource holds no random token.
func isARN(value string) bool { return arn.MatchString(value) && !holdsRandomToken(value) }

// isHostList reports whether value is host names or ARNs, two or more, separated
// by commas, semicolons or spaces.
func isHostList(value string) bool {
	items := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || unicode.IsSpace(r) })
	return len(items) > 1 && !slices.ContainsFunc(items, func(item string) bool { return !isHost(item) && !isARN(item) })
}

// flag matches a flag: a dash and a letter, as in -O2, -Xmx2g, -DNAME=value and
// -Wl,-rpath,/opt/lib, or two and a name, as in --enable-source-maps.
var flag = regexp.MustCompile(`^--?[A-Za-z]`)

// flagChars are the characters compiler, linker and JVM flags are written in.
const flagChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.+-=/:,@%"

// isFlagList reports whether value is two or more flags separated by spaces, as
// CPPFLAGS and JAVA_OPTS hold, each but the first perhaps the path the flag before
// it takes, as in -isystem /usr/include, with no random token in any and none that
// can hold a password.
func isFlagList(value string) bool {
	items := strings.Fields(value)
	if len(items) < 2 || holdsRandomToken(value) {
		return false
	}
	for i, item := range items {
		path := i > 0 && flag.MatchString(items[i-1]) && !strings.Contains(items[i-1], "=") && looksLikePath(item)
		if strings.Trim(item, flagChars) != "" || !path && (!flag.MatchString(item) || passwordFlag(item)) {
			return false
		}
	}
	return true
}

// pFlags are the compiler's flags, and Terraform's -parallelism, that start as
// mysql's -p<password> does.
var pFlags = []string{"-pg", "-pie", "-pipe", "-pthread", "-pthreads", "-pedantic", "-pedantic-errors", "-parallelism"}

// pFlag reports whether item is one of pFlags as written: none takes a value but
// -parallelism, which takes a number, so -pg=<password> is still mysql's -p.
func pFlag(item string) bool {
	name, value, set := strings.Cut(item, "=")
	if name == "-parallelism" {
		return !set || value != "" && strings.Trim(value, "0123456789") == ""
	}
	return slices.Contains(pFlags, item)
}

// agentFlags are the JVM's flags that start as -a<user>:<password> does.
var agentFlags = []string{"-agentlib:", "-agentpath:"}

// loginFlags are the flags a login is attached to, with what can join its user and
// password: curl's -u<user>:<password>, lftp's -u<user>,<password>, redis-cli's
// -a<user>:<password>, and smbclient's -U<user>%<password> and curl's proxy login
// -U<user>:<password>. No macro's name, as in -UNDEBUG, holds % or :.
var loginFlags = map[string]string{"-u": ":,", "-a": ":", "-U": "%:"}

// passwordFlag reports whether item, a flag, can hold a password, which a person
// chooses and so looks no more random than a flag: its name, before any = or path,
// or the keys it sets, one or a list, all before its value's last =, has a word for
// a credential, as -Djavax.net.ssl.keyStorePassword=<password> and
// -var=db_password=<password> do, it is mysql's -p<password>, = and all, or isql's
// -P<password>, as Maven's -P<profile> looks too but mysql's -P<port> does not, it
// is a login attached to a flag loginFlags names, its name says user and it is set
// to a user and password joined by : or %, as smbclient's --user=<user>%<password>
// is, or it is set to a user and password rather than to a host and port.
func passwordFlag(item string) bool {
	name, value, _ := strings.Cut(item, "=")
	name, _, _ = strings.Cut(name, "/")
	keys := value[:max(strings.LastIndex(value, "="), 0)]
	user, password, login := strings.Cut(value, ":")
	seps, attached := loginFlags[item[:2]]
	agent := slices.ContainsFunc(agentFlags, func(f string) bool { return strings.HasPrefix(item, f) })
	return holdsCredentialWord(name) || holdsCredentialWord(keys) ||
		len(item) > 2 && strings.HasPrefix(item, "-p") && !pFlag(item) ||
		strings.HasPrefix(item, "-P") && strings.Trim(item[2:], "0123456789") != "" ||
		attached && !agent && isLogin(item[2:], seps) ||
		strings.Contains(strings.ToUpper(name), "USER") && isLogin(value, ":%") ||
		login && user != "" && strings.Trim(password, "0123456789") != "" && !strings.HasPrefix(password, "/")
}

// isLogin reports whether s is a user and a password joined by one of seps.
func isLogin(s, seps string) bool {
	i := strings.IndexAny(s, seps)
	return i > 0 && i < len(s)-1
}

// digestNames end the names of variables that hold digests, as GIT_COMMIT_SHA and
// IMAGE_DIGEST do.
var digestNames = []string{"_SHA", "_SHA256", "_COMMIT", "_DIGEST", "_HASH", "_CHECKSUM", "_FINGERPRINT", "_ETAG", "_INTEGRITY"}

// namesDigest reports whether a variable called name holds a digest: its name
// ends as a digest's does, with no word for a credential in it, as
// LEDGER_HMAC_SHA256 has.
func namesDigest(name string) bool {
	upper := strings.ToUpper(name)
	return !holdsCredentialWord(name) && slices.ContainsFunc(digestNames, func(suffix string) bool { return strings.HasSuffix(upper, suffix) })
}

// credentialWords are words for a credential, as in a name or a comment. PASS is
// in PASSWORD, CRED in CREDENTIALS and PW in PWD; a login can be a password, and
// an Erlang COOKIE is a shared secret.
var credentialWords = []string{"HMAC", "SIGNING", "SECRET", "KEY", "TOKEN", "PASS", "PW", "AUTH", "CRED", "LOGIN", "COOKIE"}

// holdsCredentialWord reports whether s holds a word for a credential, in any case.
func holdsCredentialWord(s string) bool {
	upper := strings.ToUpper(s)
	return slices.ContainsFunc(credentialWords, func(w string) bool { return strings.Contains(upper, w) })
}

// digestSizes are how many bytes each algorithm's digest has.
var digestSizes = map[string]int{"md5": 16, "sha1": 20, "sha224": 28, "sha256": 32, "sha384": 48, "sha512": 64}

// digestShaped reports whether value is written as a digest is where no algorithm
// names it: hex of a digest's length, or base64 of one holding +, /, -, _ or
// padding. A token of letters and digits alone can decode to a digest's length
// too, as any 64 of them do.
func digestShaped(value string) bool {
	sizes := slices.Collect(maps.Values(digestSizes))
	if len(value)%2 == 0 && slices.Contains(sizes, len(value)/2) && isHex(value) {
		return true
	}
	if !strings.ContainsAny(value, "+/-_=") {
		return false
	}
	return slices.ContainsFunc([]*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}, func(e *base64.Encoding) bool {
		b, err := e.Strict().DecodeString(value)
		return err == nil && slices.Contains(sizes, len(b))
	})
}

// isDigest reports whether value is a digest written with its algorithm, as in
// sha256:<hex>, sha512-<base64> and SHA256:<base64>: hex or base64 of exactly the
// algorithm's length.
func isDigest(value string) bool {
	i := strings.IndexAny(value, ":-")
	if i < 0 {
		return false
	}
	size, ok := digestSizes[strings.ToLower(value[:i])]
	if !ok {
		return false
	}
	digest := value[i+1:]
	if hexDigest(value[:i], digest) {
		return true
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := encoding.DecodeString(digest); err == nil && len(b) == size {
			return true
		}
	}
	return false
}

// pinnedImage matches an image reference pinned by its digest, as in
// ghcr.io/example/api@sha256:<hex> and nginx:1.25@sha256:<hex>: a registry host
// and port, perhaps, then a lowercase path, perhaps a tag, and the digest. It
// captures what comes before the digest.
var pinnedImage = regexp.MustCompile(`^((?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9._-]+(?:/[a-z0-9._-]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?)@sha256:[0-9a-f]{64}$`)

// isPinnedImage reports whether value is an image reference pinned by its digest,
// with no random token in its name or tag.
func isPinnedImage(value string) bool {
	m := pinnedImage.FindStringSubmatch(value)
	return m != nil && !holdsRandomToken(m[1])
}
