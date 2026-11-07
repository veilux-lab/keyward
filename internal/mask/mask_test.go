package mask

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/url"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/veilux-lab/keyward/internal/handle"
)

// token is fake, and 40 bytes long.
const token = "ghp_FakeMaskTestToken0000000000000000000"

func one(name, value string) []Secret { return []Secret{{Name: name, Value: value}} }

// whole passes in as one write and returns all the output.
func whole(f *filter, in string) string {
	return string(f.write([]byte(in))) + string(f.flush(true))
}

// chunked passes in as writes of the given sizes, with no pause between them.
func chunked(f *filter, in string, sizes []int) string {
	var out []byte
	for _, n := range sizes {
		out = append(out, f.write([]byte(in[:n]))...)
		in = in[n:]
	}
	out = append(out, f.write([]byte(in))...)
	return string(append(out, f.flush(true)...))
}

func TestPlaceholderIsNotAReference(t *testing.T) {
	p := Placeholder("github-token")
	if p != "cap://github-token#masked" {
		t.Errorf("Placeholder = %q", p)
	}
	if _, err := handle.Parse(p); err == nil {
		t.Errorf("%s parses as a reference", p)
	}
}

func TestSelectSkipsShortAndPublicValues(t *testing.T) {
	got := Select(map[string]string{
		"short":  "1234567",
		"spaced": "  1234567 \n",
		"user":   "nnwokolo-user",
		"token":  token,
		"other":  "another-fake-secret",
	}, []string{"/Users/nnwokolo-user/dev", "cap://unresolved"})
	want := []Secret{{Name: "other", Value: "another-fake-secret"}, {Name: "token", Value: token}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Select = %v, want %v", got, want)
	}
}

// Each encoding is produced by a real encoder, not by the code under test.
func TestHidesTheValueInCommonEncodings(t *testing.T) {
	value := `Fake+Pa/ss"w\rd=é<&>~ 9!`
	goJSON, _ := json.Marshal(value)
	var plainJSON bytes.Buffer
	enc := json.NewEncoder(&plainJSON)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
	inner := func(b []byte) string { return strings.TrimSpace(string(b))[1 : len(strings.TrimSpace(string(b)))-1] }
	encoded := map[string]string{
		"raw":            value,
		"Go JSON":        inner(goJSON),
		"JSON":           inner(plainJSON.Bytes()),
		"PHP JSON":       strings.ReplaceAll(inner(plainJSON.Bytes()), "/", `\/`),
		"Python JSON":    strings.ReplaceAll(inner(plainJSON.Bytes()), "é", `\u00e9`),
		"Gson JSON":      inner(gsonJSON(value)),
		".NET JSON":      inner(dotnetJSON(value)),
		"query":          url.QueryEscape(value),
		"path":           url.PathEscape(value),
		"base64":         base64.StdEncoding.EncodeToString([]byte(value)),
		"url base64":     base64.URLEncoding.EncodeToString([]byte(value)),
		"HTTP Basic":     base64.StdEncoding.EncodeToString([]byte("nnwokolo:" + value)),
		"after one byte": base64.RawStdEncoding.EncodeToString([]byte("a" + value + "tail")),
	}
	for kind, text := range encoded {
		out := whole(newFilter(one("pw", value)), "seen: "+text+" end\n")
		if !strings.Contains(out, Placeholder("pw")) {
			t.Errorf("%s: %q not hidden: %q", kind, text, out)
		}
		if strings.Contains(out, text) {
			t.Errorf("%s: output still shows %q", kind, text)
		}
	}
}

// A URL's user info keeps characters that other URL encoders escape, in Go and
// in the URL standard that Node and browsers follow. JSON encoders write a
// backspace and a form feed as \b and \f, and Go's an invalid byte as U+FFFD.
func TestHidesTheValueInAURLsUserInfoAndInJSONsOtherEscapes(t *testing.T) {
	goURL := func(password string) string {
		return (&url.URL{Scheme: "postgres", User: url.UserPassword("user", password), Host: "db"}).String()
	}
	goJSON := func(value string) string {
		b, _ := json.Marshal(value)
		return string(b)
	}
	for name, tc := range map[string]struct{ value, text string }{
		"Go URL with , and ;":   {"Fake,comma;semi@at=eq", goURL("Fake,comma;semi@at=eq")},
		"Go URL with @ and $":   {"Fake@at$dollar1234", goURL("Fake@at$dollar1234")},
		"Go URL with : and =":   {"Fake:colon=eq123456", goURL("Fake:colon=eq123456")},
		"Node URL":              {"Fake,comma;semi@at=eq", "postgres://user:Fake,comma%3Bsemi%40at%3Deq@db"},
		"JSON with \\b and \\f": {"Fake\bpass\fword99", goJSON("Fake\bpass\fword99")},
		"Go JSON of a bad byte": {"Fake\xffpassword99", goJSON("Fake\xffpassword99")},
		"HTML-safe, a bad byte": {"Fake<\xffpassword99", goJSON("Fake<\xffpassword99")},
	} {
		out := whole(newFilter(one("pw", tc.value)), "seen: "+tc.text+" end\n")
		if !strings.Contains(out, Placeholder("pw")) || strings.Contains(out, "word99") || strings.Contains(out, "semi") || strings.Contains(out, "1234") {
			t.Errorf("%s: %q not hidden: %q", name, tc.text, out)
		}
	}
}

// A form's body, as URLSearchParams and Ruby's encode_www_form write it, escapes
// ~ and keeps *, and as PHP's urlencode and http_build_query write it, escapes
// both, each with + for a space. node, ruby and php printed these.
func TestHidesTheValueInAFormBody(t *testing.T) {
	for name, tc := range map[string]struct{ value, text string }{
		"URLSearchParams":              {"Fake~Pass*word(2026)!x", "Fake%7EPass*word%282026%29%21x"},
		"URLSearchParams with a space": {"Fake~Pass word*12", "Fake%7EPass+word*12"},
		"URLSearchParams with * and !": {"Fake*Pass!word2026", "Fake*Pass%21word2026"},
		"PHP's urlencode":              {"Fake~Pass*word(2026)!x", "Fake%7EPass%2Aword%282026%29%21x"},
		"PHP's urlencode with a space": {"Fake~Pass word*12", "Fake%7EPass+word%2A12"},
		"any of them, with two ~":      {"Fake~Passw0rd~99", "Fake%7EPassw0rd%7E99"},
	} {
		f := newFilter(one("pw", tc.value))
		if out := whole(f, "body: k="+tc.text+"&x=1\n"); out != "body: k="+Placeholder("pw")+"&x=1\n" || !f.masked["pw"] {
			t.Errorf("%s: %q not hidden: %q", name, tc.text, out)
		}
	}
}

// wgKey is a fake WireGuard key: base64 with its padding.
const wgKey = "FakeWireGuard+PrivateKey/000000000000000000="

// Gson writes = as \u003d, so a base64 value's padding, and .NET writes + as
// \u002B: the value would otherwise show all but those.
func TestHidesABase64ValueAsGsonAndDotNetWriteIt(t *testing.T) {
	for _, value := range []string{"FakeToken+abc/def0123==", wgKey, "Fake=Passw0rd99", "Fake<Pass'w0rd99"} {
		for name, encode := range map[string]func(any) []byte{"Gson": gsonJSON, ".NET": dotnetJSON} {
			doc := encode(map[string]string{"token": value})
			f := newFilter(one("pw", value))
			if out := whole(f, string(doc)+"\n"); out != `{"token":"`+Placeholder("pw")+`"}`+"\n" || !f.masked["pw"] {
				t.Errorf("%s, by %s: output = %s", value, name, out)
			}
		}
	}
}

// PHP's json_encode with JSON_HEX_TAG, APOS, AMP and QUOT, which Symfony uses,
// escapes < > & ' " in upper case hex. Python's repr, PHP's var_export and
// Node's inspect double each backslash, and escape a quote only sometimes.
func TestHidesTheValueAsPHPAndPythonQuoteIt(t *testing.T) {
	for name, tc := range map[string]struct{ value, text string }{
		"PHP JSON with HEX flags":         {`Fake&Pass'w0rd<9>+x==`, `"Fake\u0026Pass\u0027w0rd\u003C9\u003E+x=="`},
		"PHP JSON, also / and é":          {`Fake"Q/é<x>12`, `"Fake\u0022Q\/\u00e9\u003Cx\u003E12"`},
		"PHP JSON, / and é unescaped":     {`Fake"Q/é<x>12`, `"Fake\u0022Q/é\u003Cx\u003E12"`},
		"PHP var_export":                  {`Fake\Pass'word\9x`, `'Fake\\Pass\'word\\9x'`},
		"Python repr":                     {`Fake\Pass"word\9x`, `'Fake\\Pass"word\\9x'`},
		"Python repr with both quotes":    {`Fake\Pass's"q12`, `'Fake\\Pass\'s"q12'`},
		"Python repr with a single quote": {`Fake\Pass'word\9x`, `"Fake\\Pass'word\\9x"`},
	} {
		out := whole(newFilter(one("pw", tc.value)), "seen: "+tc.text+" end\n")
		if !strings.Contains(out, Placeholder("pw")) || strings.Contains(out, "Pass") || strings.Contains(out, "Q") {
			t.Errorf("%s: %s not hidden: %q", name, tc.text, out)
		}
	}
}

// Go's and Gson's JSON encoders, and PHP's with JSON_UNESCAPED_UNICODE, escape
// U+2028 and U+2029, which end a line in JavaScript, but write the rest of what
// is beyond ASCII as is. Go's before json/v2 writes a byte that is not UTF-8 as
// \ufffd. The PHP and old Go strings came from php and GOEXPERIMENT=nojsonv2.
func TestHidesTheValueInJSONThatEscapesOnlyLineSeparators(t *testing.T) {
	for name, tc := range map[string]struct{ value, text string }{
		"Go":                            {"Fake\u2028Passw0rdé2026", string(goJSON("Fake\u2028Passw0rdé2026", true))},
		"Go without HTML escapes":       {"Fake\u2029<Pass>é2026", string(goJSON("Fake\u2029<Pass>é2026", false))},
		"Gson":                          {"Fake\u2028Pass=w0rdé", string(gsonJSON("Fake\u2028Pass=w0rdé"))},
		"PHP":                           {"Fake\u2028Pass/w0rdé2026", `"Fake\u2028Pass\/w0rdé2026"`},
		"PHP with HEX flags":            {"Fake\u2029<Pass>é", `"Fake\u2029\u003CPass\u003Eé"`},
		"Go before json/v2, a bad byte": {"Fake\xffPassw0rdé2026", `"Fake\ufffdPassw0rdé2026"`},
	} {
		f := newFilter(one("pw", tc.value))
		if out := whole(f, "x "+tc.text+" y\n"); out != `x "`+Placeholder("pw")+`" y`+"\n" || !f.masked["pw"] {
			t.Errorf("%s: %s not hidden: %q", name, tc.text, out)
		}
	}
}

// Whatever comes before and after the value, one of its base64 forms is in the
// encoding, and it covers all but a few of the value's bytes.
func TestBase64FormsCoverEveryAlignment(t *testing.T) {
	value := []byte(token)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		forms := inBase64(value, enc)
		for before := range 6 {
			for after := range 4 {
				text := enc.EncodeToString(append(append(bytes.Repeat([]byte{'u'}, before), value...), bytes.Repeat([]byte{'z'}, after)...))
				found := false
				for _, f := range forms {
					found = found || strings.Contains(text, string(f))
				}
				if !found {
					t.Errorf("%d bytes before, %d after: no form in %s", before, after, text)
				}
			}
		}
		for _, f := range forms {
			if len(f) < len(value)*4/3-3 {
				t.Errorf("form %q covers too little of the value", f)
			}
		}
	}
}

func TestPassesOrdinaryOutputAtOnce(t *testing.T) {
	f := newFilter(one("t", token))
	if got := string(f.write([]byte("hello, world\n"))); got != "hello, world\n" {
		t.Errorf("write = %q", got)
	}
	if f.holding() {
		t.Error("holding after a line that cannot start a secret")
	}
}

func TestHoldsTheStartOfASecretForTheRest(t *testing.T) {
	f := newFilter(one("t", token))
	if got := string(f.write([]byte("token: " + token[:5]))); got != "token: " {
		t.Errorf("first write = %q, want the text before the secret", got)
	}
	if !f.holding() {
		t.Fatal("not holding the start of the secret")
	}
	if got := string(f.write([]byte(token[5:] + "\n"))); got != Placeholder("t")+"\n" {
		t.Errorf("second write = %q", got)
	}
}

var streamed = strings.Join([]string{
	"plain line\n",
	"curl: Enter host password for user '" + token + "':",
	`{"error":"bad token \"` + token + `\""}` + "\n",
	"Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("nnwokolo:"+token)) + "\n",
	"https://example.com/hook?key=" + url.QueryEscape(token) + "&x=1\n",
	token + token + " twice\n",
	"ends with a start: " + token[:6],
}, "")

// However the output is split into reads, the result is the same.
func TestSplittingTheOutputChangesNothing(t *testing.T) {
	want := whole(newFilter(one("t", token)), streamed)
	if strings.Contains(want, token) || strings.Count(want, Placeholder("t")) != 6 {
		t.Fatalf("whole output = %q", want)
	}
	for n := 1; n < len(streamed); n++ {
		if got := chunked(newFilter(one("t", token)), streamed, []int{n}); got != want {
			t.Fatalf("split at %d:\n got %q\nwant %q", n, got, want)
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 500 {
		var sizes []int
		for left := len(streamed); left > 0; {
			n := min(left, 1+r.IntN(24))
			sizes, left = append(sizes, n), left-n
		}
		if got := chunked(newFilter(one("t", token)), streamed, sizes[:len(sizes)-1]); got != want {
			t.Fatalf("reads of %v:\n got %q\nwant %q", sizes, got, want)
		}
	}
}

func TestAPauseLetsAShortStartThroughButHidesTheRest(t *testing.T) {
	f := newFilter(one("t", token))
	out := string(f.write([]byte("x " + token[:3])))
	out += string(f.flush(false))
	if out != "x "+token[:3] {
		t.Errorf("after the pause = %q, want the start let through", out)
	}
	if got := string(f.write([]byte(token[3:] + " y\n"))); got != Placeholder("t")+" y\n" {
		t.Errorf("the rest = %q, want it hidden", got)
	}
}

func TestAPauseHidesALongStartAndTheRest(t *testing.T) {
	f := newFilter(one("t", token))
	if got := string(f.write([]byte(token[:20]))) + string(f.flush(false)); got != Placeholder("t") {
		t.Errorf("after the pause = %q, want a placeholder", got)
	}
	if got := string(f.write([]byte(token[20:] + " y\n"))); got != " y\n" {
		t.Errorf("the rest = %q, want only what follows the secret", got)
	}
}

func TestAPauseAfterAStartThatGoesNowhereLosesNothing(t *testing.T) {
	f := newFilter(one("t", token))
	out := string(f.write([]byte("a "+token[:3]))) + string(f.flush(false))
	out += string(f.write([]byte("zzz\n")))
	if want := "a " + token[:3] + "zzz\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestPausesWithinASecretLetThroughLessThanItsLength(t *testing.T) {
	f := newFilter(one("t", token))
	var out string
	for _, piece := range []string{token[:3], token[3:6], token[6:12], token[12:] + "\n"} {
		out += string(f.write([]byte(piece))) + string(f.flush(false))
	}
	if want := token[:6] + Placeholder("t") + "\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestTheEndHidesOnlyALongStart(t *testing.T) {
	if got := whole(newFilter(one("t", token)), "cut off: "+token[:20]); got != "cut off: "+Placeholder("t") {
		t.Errorf("long start at the end = %q", got)
	}
	if got := whole(newFilter(one("t", token)), "cut off: "+token[:3]); got != "cut off: "+token[:3] {
		t.Errorf("short start at the end = %q", got)
	}
}

// serviceAccount is a fake Google Cloud service account key: a credentials file
// that holds a private key in a JSON string. Its key ID is split in two, so no
// source line holds the shape that secret scanners look for.
const serviceAccount = `{
  "type": "service_account",
  "project_id": "fake-project-123456",
  "private_key_id": "0123456789abcdef` + `0123456789abcdef01234567",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvFakeServiceAccountKeyLineOne0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAA\nFakeServiceAccountKeyLineTwo1/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\nFakeLastLine9==\n-----END PRIVATE KEY-----\n",
  "client_email": "fake@fake-project-123456.iam.gserviceaccount.com",
  "client_id": "123456789012345678901",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/fake%40fake-project-123456.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
`

// A value that spans lines, like a key or a credentials file, is hidden where
// the command prints it whole, as stored or inside a JSON string, also one
// inside another. A line of it on its own, or the value re-indented,
// reformatted or with CRLF line ends, shows as written and names no secret,
// but its first lines at the end of the output are its start, which is hidden
// there as any value's long start is.
func TestHidesAValueThatSpansLinesOnlyWhole(t *testing.T) {
	lines := []string{
		"-----BEGIN FAKE PRIVATE KEY-----",
		"MIIEvFakeKeyLineOne0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"FakeLineTwo16By=",
		"-----END FAKE PRIVATE KEY-----",
	}
	key := strings.Join(lines, "\n") + "\n"
	for kind, value := range map[string]string{"a key": key, "a credentials file": serviceAccount} {
		doc, _ := json.Marshal(map[string]string{"value": value})
		result, _ := json.Marshal(map[string]string{"text": string(doc)})
		for name, text := range map[string]string{"as stored": value, "in JSON": string(doc), "in JSON inside a JSON string": string(result)} {
			f := newFilter(one("k", value))
			out := whole(f, text)
			if strings.Contains(out, "Line") || strings.Count(out, Placeholder("k")) != 1 || text != value && !json.Valid([]byte(out)) || !f.masked["k"] {
				t.Errorf("%s, %s: output = %q, masked %v", kind, name, out, f.masked)
			}
		}
	}
	var reformatted bytes.Buffer
	_ = json.Indent(&reformatted, []byte(serviceAccount), "", "    ")
	for name, tc := range map[string]struct{ value, text string }{
		"a key's line on its own":        {key, lines[1] + "\n"},
		"a key re-indented":              {key, "key: |\n  " + strings.Join(lines, "\n  ") + "\n"},
		"a key with CRLF line ends":      {key, strings.Join(lines, "\r\n") + "\r\n"},
		"a credentials file reformatted": {serviceAccount, reformatted.String()},
	} {
		f := newFilter(one("k", tc.value))
		if out := whole(f, tc.text); out != tc.text || len(f.masked) != 0 {
			t.Errorf("%s: output = %q, masked %v; want it as written", name, out, f.masked)
		}
	}
	// As grep or head -n 1 may print another file that starts the same way. The
	// fake key ID is split in two so that no source line holds an AWS key's shape.
	creds := "[default]\naws_access_key_id = AKIA" + "FAKEFAKEFAKE0000\naws_secret_access_key = FakeSecretAccessKey0123456789\n"
	f := newFilter(one("creds", creds))
	if out := whole(f, "3:[default]\n"); out != "3:"+Placeholder("creds") || !f.masked["creds"] {
		t.Errorf("a file's first line at the end: output = %q, masked %v", out, f.masked)
	}
}

// pem returns a fake PEM block of kind with one line of body.
func pem(kind, body string) string {
	return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----\n"
}

// Every key or certificate of a kind starts with the same armour line. At a
// pause or the end of the output, a held start of a value that is no more than
// that line and its line end, or a start of it, goes out as written and names
// no secret. A start that shows more, or the value's rest after the pause, is
// hidden.
func TestAPauseLetsAnArmourLineThrough(t *testing.T) {
	key := pem("RSA PRIVATE KEY", "MIIEowFakeKeyLine0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nFakeLastLine9==")
	other := pem("RSA PRIVATE KEY", "MIIEpAOtherFakeKeyLine1+/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	cert := pem("CERTIFICATE", "MIIBFakeCertificateLine2+/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	otherCert := pem("CERTIFICATE", "MIIBOtherFakeCertificate3+/DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD")
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	inJSON := func(s string) string { b, _ := json.Marshal(s); return string(b[1 : len(b)-1]) }
	// The armour line and its line end: 32 bytes, 33 with CRLF or in JSON.
	armour := "-----BEGIN RSA PRIVATE KEY-----\n"
	n := len(armour)
	for name, tc := range map[string]struct {
		value  string
		pieces []string // each followed by a pause
		want   string
	}{
		"grep for armour":           {key, []string{"certs/ca.pem:1:-----BEGIN CERTIFICATE-----\nkeys/other.key:1:" + armour}, ""},
		"a start of the armour":     {key, []string{"x " + armour[:20]}, ""},
		"another key":               {key, []string{armour, other[n:]}, ""},
		"another key with CRLF":     {crlf(key), []string{crlf(other)[:n+1], crlf(other)[n+1:]}, ""},
		"another key in JSON":       {key, []string{`{"key":"` + inJSON(other)[:n+1], inJSON(other)[n+1:] + `"}`}, ""},
		"another certificate":       {cert + key, []string{otherCert[:28], otherCert[28:]}, ""},
		"the key":                   {key, []string{armour, key[n:]}, armour + Placeholder("k") + "\n"},
		"the key in JSON":           {key, []string{`{"key":"` + inJSON(key)[:n+1], inJSON(key)[n+1:] + `"}`}, `{"key":"` + inJSON(key)[:n+1] + Placeholder("k") + `\n"}`},
		"a byte past the armour":    {key, []string{key[:n+1]}, Placeholder("k")},
		"a byte past it, with CRLF": {crlf(key), []string{crlf(key)[:n+2]}, Placeholder("k")},
	} {
		f := newFilter(one("k", tc.value))
		var in, out string
		for _, piece := range tc.pieces {
			in, out = in+piece, out+string(f.write([]byte(piece)))+string(f.flush(false))
		}
		out += string(f.flush(true))
		if want := cmp.Or(tc.want, in); out != want || f.masked["k"] != (tc.want != "") {
			t.Errorf("%s: output = %q, masked %v; want %q", name, out, f.masked, want)
		}
	}
}

// sshLine is the first line of base64 of every unencrypted ed25519 key in
// OpenSSH's format, as ssh-keygen writes it.
const sshLine = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"

// sshKey returns a fake ed25519 key in OpenSSH's format, with body after that line.
func sshKey(body string) string {
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + sshLine + "\n" + body + "\n-----END OPENSSH PRIVATE KEY-----\n"
}

// An OpenSSH key's first line of base64 holds nothing secret, only how the key
// is stored, and every unencrypted key of a type has the same one. So a pause
// after it, as head -n 2 of a key makes, lets it out with the armour line, but
// not a byte more. A key stored with its base64 on one line has only its
// armour line let out.
func TestAPauseLetsAnOpenSSHKeysFirstLineThrough(t *testing.T) {
	key := sshKey("QyNTUxOQAAACFakeEd25519KeyLine0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	other := sshKey("QyNTUxOQAAACOtherFakeEd25519Line1+/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
	oneLine := strings.Replace(key, sshLine+"\n", sshLine, 1)
	inJSON := func(s string) string { b, _ := json.Marshal(s); return string(b[1 : len(b)-1]) }
	// The armour line and that first line, with their line ends: 107 bytes, 109
	// in JSON.
	n := len("-----BEGIN OPENSSH PRIVATE KEY-----\n" + sshLine + "\n")
	for name, tc := range map[string]struct {
		value  string
		pieces []string // each followed by a pause
		want   string
	}{
		"head -n 2 of another key": {key, []string{"x " + other[:n]}, ""},
		"another key":              {key, []string{other[:n], other[n:]}, ""},
		"another key in JSON":      {key, []string{`{"key":"` + inJSON(other)[:n+2], inJSON(other)[n+2:] + `"}`}, ""},
		"the key":                  {key, []string{key[:n], key[n:]}, key[:n] + Placeholder("k") + "\n"},
		"a byte past that line":    {key, []string{key[:n+1]}, Placeholder("k")},
		"a key on one line":        {oneLine, []string{oneLine[:strings.Index(oneLine, "\n-----END")+1]}, Placeholder("k")},
	} {
		f := newFilter(one("k", tc.value))
		var in, out string
		for _, piece := range tc.pieces {
			in, out = in+piece, out+string(f.write([]byte(piece)))+string(f.flush(false))
		}
		out += string(f.flush(true))
		if want := cmp.Or(tc.want, in); out != want || f.masked["k"] != (tc.want != "") {
			t.Errorf("%s: output = %q, masked %v; want %q", name, out, f.masked, want)
		}
	}
}

// Only a value that starts with an armour line has one to let through. One that
// starts as an armour line does, but goes on otherwise, shows no more at a
// pause than any other value: under MinLength bytes and under half of it. Nor
// does a shorter key that the same start may begin let it out.
func TestAPauseLetsOutOnlyTheArmourLineAValueStartsWith(t *testing.T) {
	key := pem("RSA PRIVATE KEY", "MIIEowFakeKeyLine0+/AAAAAAAA")
	long := "-----BEGIN RSxyz" + strings.Repeat("FakePass", 12)
	for name, tc := range map[string]struct {
		secrets []Secret
		pieces  []string // each followed by a pause
	}{
		"half of it":            {one("s", "-----Xy9Qz"), []string{"a -----", "Xy9Qz b\n"}},
		"dashes":                {one("s", "--------"), []string{"a -----", "--- b\n"}},
		"all but its last byte": {one("s", "-----BEGIN XY"), []string{"a -----BEGIN X", "Y b\n"}},
		"more than half":        {one("s", "-----BEGIN-pass-1"), []string{"a -----BEGIN", "-pass-1 b\n"}},
		"a long start":          {one("s", "-----BEGIN-FakeLongPassword-2026"), []string{"a -----BEGIN", "-FakeLongPassword-2026 b\n"}},
		"a key's start too":     {[]Secret{{Name: "k", Value: key}, {Name: "s", Value: long}}, []string{"a " + long[:13], long[13:] + " b\n"}},
	} {
		f := newFilter(tc.secrets)
		var out string
		for _, piece := range tc.pieces {
			out += string(f.write([]byte(piece))) + string(f.flush(false))
		}
		out += string(f.flush(true))
		if want := "a " + Placeholder("s") + " b\n"; out != want || len(f.masked) != 1 || !f.masked["s"] {
			t.Errorf("%s: output = %q, masked %v; want %q", name, out, f.masked, want)
		}
	}
}

// A label may hold lower case, hyphens and dots, as OpenVPN's keys and DH
// parameters' do, so their armour lines go out at a pause too.
func TestAPauseLetsAnArmourLineThroughWhateverItsLabel(t *testing.T) {
	for _, label := range []string{"OpenVPN Static key V1", "OpenVPN tls-crypt-v2 client key", "X9.42 DH PARAMETERS"} {
		key := pem(label, "FakeKeyLine0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		other := pem(label, "OtherFakeKeyLine1+/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
		n := strings.Index(other, "\n") + 1
		f := newFilter(one("k", key))
		out := string(f.write([]byte(other[:n]))) + string(f.flush(false))
		out += string(f.write([]byte(other[n:]))) + string(f.flush(true))
		if out != other || len(f.masked) != 0 {
			t.Errorf("%s: output = %q, masked %v; want it as written", label, out, f.masked)
		}
	}
}

// A stored key's URL-encoded forms start with -----BEGIN but have no armour
// line, as %20 or + follows. So output that ends or pauses 8 to 10 bytes into
// an armour line, its key's or another's, still goes out as written and names
// nothing. The key itself is hidden, from a pause in its armour line or after it.
func TestAPauseLetsTheStartOfAnArmourLineThrough(t *testing.T) {
	cert := pem("CERTIFICATE", "MIIBFakeCertificateLine2+/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
	for kind, keys := range map[string][2]string{
		"PEM": {pem("RSA PRIVATE KEY", "MIIEowFakeKeyLine0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			pem("RSA PRIVATE KEY", "MIIEpAOtherFakeKeyLine1+/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")},
		"OpenSSH": {sshKey("QyNTUxOQAAACFakeEd25519KeyLine0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			sshKey("QyNTUxOQAAACOtherFakeEd25519Line1+/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")},
		"OpenVPN": {pem("OpenVPN Static key V1", "FakeKeyLine0+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			pem("OpenVPN Static key V1", "OtherFakeKeyLine1+/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")},
	} {
		key := keys[0]
		// paused writes each piece, with a pause after all but the last, which the
		// output ends after.
		paused := func(pieces ...string) (string, map[string]bool) {
			f := newFilter(one("k", key))
			var out string
			for i, piece := range pieces {
				if out += string(f.write([]byte(piece))); i < len(pieces)-1 {
					out += string(f.flush(false))
				}
			}
			return out + string(f.flush(true)), f.masked
		}
		for n := 8; n <= 10; n++ {
			for _, line := range []string{key, keys[1], cert} {
				if out, masked := paused("x " + line[:n]); out != "x "+line[:n] || len(masked) != 0 {
					t.Errorf("%s, ending %d bytes into %.20q: output = %q, masked %v", kind, n, line, out, masked)
				}
			}
			for _, line := range []string{keys[1], cert} {
				if out, masked := paused("x "+line[:n], line[n:]); out != "x "+line || len(masked) != 0 {
					t.Errorf("%s, pausing %d bytes into %.20q: output = %q, masked %v", kind, n, line, out, masked)
				}
			}
			if out, masked := paused(key[:n], key[n:]); out != key[:n]+Placeholder("k")+"\n" || !masked["k"] {
				t.Errorf("%s, pausing %d bytes into the key: output = %q, masked %v", kind, n, out, masked)
			}
		}
		line := key[:strings.Index(key, "\n")+1]
		if out, masked := paused(line, key[len(line):]); out != line+Placeholder("k")+"\n" || !masked["k"] {
			t.Errorf("%s, pausing after the key's armour line: output = %q, masked %v", kind, out, masked)
		}
	}
}

// The armour line a value starts with ends with its line end, as written or in
// JSON once or twice. Its label is printable ASCII other than - and \, with a
// single - or space between. A value that starts otherwise, or that goes on
// otherwise after -----BEGIN, has none. In an OpenSSH key, the armour takes in
// the first line of base64 too, if it is at most 70 characters, as ssh-keygen
// writes it. The trials' check agrees.
func TestArmourIsTheArmourLineAValueStartsWith(t *testing.T) {
	line, ssh := "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"
	for text, want := range map[string]int{
		ssh + "\n" + sshLine + "\nQyNT":                         len(ssh) + 72,
		ssh + "\r\n" + sshLine + "\r\nQyNT":                     len(ssh) + 74,
		ssh + `\n` + sshLine + `\nQyNT`:                         len(ssh) + 74,
		ssh + `\\n` + sshLine + `\\nQyNT`:                       len(ssh) + 76,
		ssh + "\n" + sshLine[:40] + "\nQyNT":                    len(ssh) + 42,
		ssh + "\n" + sshLine + "QyNTUxOQ\nAAAA":                 len(ssh) + 1,
		ssh + "\n" + sshLine:                                    len(ssh) + 1,
		ssh + "\nAAAAB3NzaC1yc2EAAAADAQAB\nQyNT":                len(ssh) + 1,
		ssh + `\n` + sshLine[:40] + `\/x\nQyNT`:                 len(ssh) + 2,
		line + "\nMIIE":                                         len(line) + 1,
		line + "\r\nMIIE":                                       len(line) + 2,
		line + `\nMIIE`:                                         len(line) + 2,
		line + `\r\nMIIE`:                                       len(line) + 4,
		line + `\\nMIIE`:                                        len(line) + 3,
		line + `\\r\\nMIIE`:                                     len(line) + 6,
		line:                                                    0,
		line + "-\nMIIE":                                        0,
		"-----BEGIN RSA PRIVATE KEY--x\nMIIE":                   0,
		"-----BEGIN -----\nMIIE":                                0,
		"-----BEGIN XY":                                         0,
		"-----Xy9Qz":                                            0,
		"x " + line + "\nMIIE":                                  0,
		"-----BEGIN OpenVPN Static key V1-----\nFake":           38,
		"-----BEGIN OpenVPN tls-crypt-v2 client key-----\nFake": 48,
		"-----BEGIN X9.42 DH PARAMETERS-----\nFake":             36,
		`-----BEGIN A\"B-----\nFake`:                            0,
		"-----BEGIN RSA  KEY-----\nFake":                        0,
		"-----BEGIN -RSA KEY-----\nFake":                        0,
		"-----BEGIN RSA KEY -----\nFake":                        0,
	} {
		if got, check := armour([]byte(text)), armourOf([]byte(text)); got != want || check != want {
			t.Errorf("%q: armour %d, the check %d; want %d", text, got, check, want)
		}
	}
}

// A pause can cut short a start two secrets share, and its placeholder can only
// name the likelier one. The secret recorded as hidden is the one that follows.
func TestRecordsTheSecretThatFollowsAPause(t *testing.T) {
	// Fake Stripe keys, each split in two so that no source line holds the shape.
	a, b := "sk_"+"live_FakeAAAA0123456789", "sk_"+"live_FakeBBBB0123456789"
	secrets := []Secret{{Name: "a", Value: a}, {Name: "b", Value: b}}
	for rest, want := range map[string][]string{
		"BBBB0123456789\n":  {"b"},
		" and more\n":       {"a"},
		" then " + b + "\n": {"a", "b"},
	} {
		f := newFilter(secrets)
		out := string(f.write([]byte("key: sk_"+"live_Fake"))) + string(f.flush(false))
		out += string(f.write([]byte(rest))) + string(f.flush(true))
		if got := slices.Sorted(maps.Keys(f.masked)); strings.Contains(out, "BBBB") || !slices.Equal(got, want) {
			t.Errorf("then %q: output = %q, masked %v, want %v", rest, out, got, want)
		}
	}
}

func TestTheLongerOfTwoSecretsSharingAStartWins(t *testing.T) {
	secrets := []Secret{{Name: "a", Value: "abcdefgh1234"}, {Name: "b", Value: "abcdefgh1234-and-more"}}
	in := "x abcdefgh1234-and-more y\n"
	want := "x " + Placeholder("b") + " y\n"
	if got := whole(newFilter(secrets), in); got != want {
		t.Errorf("whole = %q, want %q", got, want)
	}
	for n := 1; n < len(in); n++ {
		if got := chunked(newFilter(secrets), in, []int{n}); got != want {
			t.Errorf("split at %d = %q", n, got)
		}
	}
}

func TestOverlappingSecretsShowNoByteOfEither(t *testing.T) {
	secrets := []Secret{{Name: "a", Value: "1111aaaa2222"}, {Name: "b", Value: "aaaa2222bbbb3333"}}
	if got := whole(newFilter(secrets), "<1111aaaa2222bbbb3333>"); got != "<"+Placeholder("a")+Placeholder("b")+">" {
		t.Errorf("output = %q", got)
	}
}

func TestASharedValueIsNamedOnce(t *testing.T) {
	f := newFilter([]Secret{{Name: "a", Value: token}, {Name: "b", Value: token}})
	if got := whole(f, token); got != Placeholder("a") {
		t.Errorf("output = %q", got)
	}
	if len(f.masked) != 1 || !f.masked["a"] {
		t.Errorf("masked = %v", f.masked)
	}
}

func TestJSONStaysValid(t *testing.T) {
	value := `Fake"quoted\pass/word<9>`
	text, _ := json.Marshal("key: " + value)
	doc := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + string(text) + `}]}}` + "\n"
	out := whole(newFilter(one("pw", value)), doc)
	if !json.Valid([]byte(out)) || !strings.Contains(out, Placeholder("pw")) {
		t.Errorf("output = %s", out)
	}
}

// goJSON encodes v as Go's encoder does, with its HTML escapes or without.
func goJSON(v any, html bool) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(html)
	_ = enc.Encode(v)
	return bytes.TrimSpace(b.Bytes())
}

// asciiJSON encodes v as Go's encoder does without its HTML escapes, but with
// what is beyond ASCII escaped too, and / if slash.
func asciiJSON(v any, slash bool) []byte {
	var b []byte
	for _, r := range string(goJSON(v, false)) {
		switch {
		case r == '/' && slash:
			b = append(b, `\/`...)
		case r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			b = fmt.Appendf(b, `\u%04x\u%04x`, hi, lo)
		case r >= utf8.RuneSelf:
			b = fmt.Appendf(b, `\u%04x`, r)
		default:
			b = append(b, byte(r))
		}
	}
	return b
}

// phpJSON encodes v as PHP's json_encode does with no flags, which escapes /
// and what is beyond ASCII.
func phpJSON(v any) []byte { return asciiJSON(v, true) }

// inHex returns doc, a JSON document, with each character in its strings for
// which hex returns an escape written as that, a " inside a string too.
func inHex(doc []byte, hex func(rune) string) []byte {
	var b []byte
	escaped := false
	for _, r := range string(doc) {
		switch {
		case escaped && r == '"' && hex(r) != "":
			b = append(b[:len(b)-1], hex(r)...)
		case !escaped && r != '"' && r != '\\' && hex(r) != "":
			b = append(b, hex(r)...)
		default:
			b = utf8.AppendRune(b, r)
		}
		escaped = !escaped && r == '\\'
	}
	return b
}

// hexOf returns a hex function for inHex that escapes the characters in set, and
// what is beyond ASCII if ascii, in the format given.
func hexOf(set string, ascii bool, format string) func(rune) string {
	return func(r rune) string {
		switch {
		case ascii && r > 0xFFFF:
			hi, lo := utf16.EncodeRune(r)
			return fmt.Sprintf(format+format, hi, lo)
		case strings.ContainsRune(set, r) || ascii && r >= utf8.RuneSelf:
			return fmt.Sprintf(format, r)
		}
		return ""
	}
}

// phpHexJSON encodes v as PHP's json_encode does with JSON_HEX_TAG, AMP, APOS
// and QUOT, as Symfony's JsonResponse does: also < > & ' " in upper case hex.
func phpHexJSON(v any) []byte { return inHex(phpJSON(v), hexOf(`<>&'"`, false, `\u%04X`)) }

// gsonJSON encodes v as Gson does by default: < > & = ' in lower case hex.
func gsonJSON(v any) []byte { return inHex(goJSON(v, false), hexOf("<>&='", false, `\u%04x`)) }

// dotnetJSON encodes v as .NET's System.Text.Json does by default: " ' < > & +
// ` and what is beyond ASCII in upper case hex.
func dotnetJSON(v any) []byte { return inHex(goJSON(v, false), hexOf(`"'<>&+`+"`", true, `\u%04X`)) }

// An MCP tool's result often carries a JSON document as its text, so a value in
// it is escaped twice, and the two levels may be escaped by different encoders:
// Go's, with its HTML escapes or without, as JavaScript's, Ruby's and most others'
// are, PHP's, with HEX flags or without, Python's, Gson's or .NET's.
func TestHidesTheValueInJSONInsideAJSONString(t *testing.T) {
	encoders := map[string]func(any) []byte{
		"Go":          func(v any) []byte { return goJSON(v, true) },
		"Go, no HTML": func(v any) []byte { return goJSON(v, false) },
		"PHP":         phpJSON,
		"PHP, HEX":    phpHexJSON,
		"Python":      func(v any) []byte { return asciiJSON(v, false) },
		"Gson":        gsonJSON,
		".NET":        dotnetJSON,
	}
	for _, value := range []string{`Fake"pa\ss&word9`, "Fake/Slash/word12", `Fake/"pa\ss/wörd9`, `Fake"Quote/word12`, `Fakeé"/word99`} {
		for inside, encodeInside := range encoders {
			for outside, encode := range encoders {
				inner := encodeInside(map[string]string{"token": value})
				doc := encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{
					"content":           []map[string]string{{"type": "text", "text": string(inner)}},
					"structuredContent": map[string]string{"token": value},
				}})
				f := newFilter(one("pw", value))
				out := whole(f, string(doc)+"\n")
				if strings.Contains(out, "rd") || strings.Count(out, Placeholder("pw")) != 2 || !json.Valid([]byte(out)) || !f.masked["pw"] {
					t.Errorf("%s, by %s inside %s: output = %s", value, inside, outside, out)
				}
			}
		}
	}
}

// A token of letters and digits reads the same in JSON, a URL or quotes, so its
// only other forms are those inside base64, and no more slow the filter down.
func TestATokenOfLettersAndDigitsHasOnlyItsBase64Forms(t *testing.T) {
	v := []byte(token)
	want := append([][]byte{v}, append(inBase64(v, base64.StdEncoding), inBase64(v, base64.URLEncoding)...)...)
	for _, p := range patterns(one("t", token), nil) {
		if !slices.ContainsFunc(want, func(w []byte) bool { return bytes.Equal(w, p.text) }) {
			t.Errorf("pattern %q", p.text)
		}
	}
}

// A pause lets a start too short to give anything away go out as written. A
// secret that begins anywhere in it must still be hidden when the rest comes.
func TestAPauseLetsNoSecretThrough(t *testing.T) {
	for name, tc := range map[string]struct {
		secrets []Secret
		pieces  []string // each followed by a pause
		want    string
	}{
		"starting inside what went out": {one("s", "xxxxxxyy"), []string{"xx", "xxxxxyy"}, "xx" + Placeholder("s")},
		"after its own first byte":      {one("s", "aaQ7fakeSecretValue"), []string{"id=aa", "aQ7fakeSecretValue\n"}, "id=aa" + Placeholder("s") + "\n"},
		"overlapping another": {
			[]Secret{{Name: "a", Value: "1111aaaa2222"}, {Name: "b", Value: "aaaa2222bbbb3333"}},
			[]string{"<1111", "aaaa2222bbbb3333>"}, "<1111" + Placeholder("a") + Placeholder("b") + ">",
		},
	} {
		f := newFilter(tc.secrets)
		var out string
		for _, piece := range tc.pieces {
			out += string(f.write([]byte(piece))) + string(f.flush(false))
		}
		if out += string(f.flush(true)); out != tc.want {
			t.Errorf("%s: output = %q, want %q", name, out, tc.want)
		}
	}
}

// A secret whose matches overlap one another, like one repeated character,
// must not make the filter hold the whole run of them, or take time that grows
// faster than the output.
func TestASelfOverlappingSecretIsNotHeldWhole(t *testing.T) {
	for _, tc := range []struct{ value, first, rest string }{
		{"aaaaaaaaaa", "", "a"},
		{"aXyZqW7a", "a", "XyZqW7a"},
	} {
		f := newFilter(one("s", tc.value))
		in := []byte(tc.first + strings.Repeat(tc.rest, 10<<20/len(tc.rest)))
		var out []byte
		start := time.Now()
		for len(in) > 0 {
			n := min(len(in), 32<<10)
			out = append(out, f.write(in[:n])...)
			if in = in[n:]; len(f.tail) >= f.longest {
				t.Fatalf("%s: held %d bytes", tc.value, len(f.tail))
			}
		}
		out = append(out, f.flush(true)...)
		// Well under a second a megabyte, even under the race detector.
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("%s: 10 MB took %v", tc.value, took)
		}
		if string(out) != Placeholder("s") {
			t.Errorf("%s: output = %.80q", tc.value, out)
		}
	}
}

// The output is searched for every pattern at once, so many secrets, as keyward
// run resolves without --only, or a long stored file cost little more than one
// token, even on output made of what they are, like a dump of base64.
func TestManyPatternsCostLittleMoreThanOne(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 10))
	random := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return b
	}
	var file strings.Builder
	var many []Secret
	for i := range 1000 {
		value := base64.StdEncoding.EncodeToString(random(24))
		fmt.Fprintf(&file, "KEY_%d=%s\n", i, value)
		many = append(many, Secret{Name: fmt.Sprintf("s%d", i), Value: value})
	}
	var in []byte
	for len(in) < 2<<20 {
		in = append(append(in, base64.StdEncoding.EncodeToString(random(57))...), '\n')
	}
	// fastest returns the least time of a few runs, which a busy machine slows
	// the least.
	fastest := func(secrets []Secret) time.Duration {
		pats := patterns(secrets, nil)
		best := time.Duration(1 << 62)
		for range 3 {
			f, start := filterFor(pats), time.Now()
			for at := 0; at < len(in); at += 32 << 10 {
				f.write(in[at:min(at+32<<10, len(in))])
			}
			f.flush(true)
			best = min(best, time.Since(start))
		}
		return best
	}
	alone := fastest(one("t", token))
	for name, secrets := range map[string][]Secret{"1000 secrets": many, "a file of 1000 lines": one("file", file.String())} {
		if took := fastest(secrets); took > 10*alone {
			t.Errorf("2 MB took %v with a token, %v with %s", alone, took, name)
		}
	}
}

// A secret can join two others that do not overlap, and end too far from the
// first one's start for a write to wait for it. Where writes end must not
// change which secrets the placeholder names.
func TestWhereWritesEndDoesNotChangeTheNamesShown(t *testing.T) {
	secrets := []Secret{{Name: "long", Value: "é/Fake~Value<1>"}, {Name: "key", Value: `key \\u00e9`}, {Name: "inner", Value: "Fake~Value"}}
	// long escaped twice as JSON, among its longest forms.
	in := `key \\u00e9\\/Fake~Value\\u003c1\\u003e` + "\n"
	want := whole(newFilter(secrets), in)
	if want != Placeholder("key")+"\n" {
		t.Fatalf("output = %q", want)
	}
	for n := 1; n < len(in); n++ {
		if got := chunked(newFilter(secrets), in, []int{n}); got != want {
			t.Errorf("split at %d: %q", n, got)
		}
	}
}

// At a pause, a held start of a secret that goes on from one hidden already is
// hidden with it, however short.
func TestAPauseHidesWhatGoesOnFromAHiddenSecret(t *testing.T) {
	f := newFilter([]Secret{{Name: "a", Value: "aaaaaaaaaa"}, {Name: "b", Value: "aaabbbbbbbbbbb"}})
	out := string(f.write([]byte(strings.Repeat("a", 30)+"bb"))) + string(f.flush(false))
	out += string(f.write([]byte("bbbbbbbbb\n"))) + string(f.flush(true))
	if out != Placeholder("a")+"\n" || !f.masked["a"] || !f.masked["b"] {
		t.Errorf("output = %q, masked %v", out, f.masked)
	}
}

// trial is one run of a filter: the secrets, the output a command writes, and
// how that output arrives.
type trial struct {
	secrets []Secret
	in      []byte
	sizes   []int  // the writes, in order
	pauses  []bool // whether a quiet moment follows each write
}

func (tr trial) String() string {
	return fmt.Sprintf("secrets %q\ninput %q\nwrites %v\npauses %v", tr.secrets, tr.in, tr.sizes, tr.pauses)
}

// run passes the output through a filter for pats, and returns what comes out,
// the filter, where the pauses fell in the input, its end included, and the
// most the filter held at once.
func (tr trial) run(pats []pattern) (string, *filter, []int, int) {
	f := filterFor(pats)
	var out []byte
	var pauses []int
	at, held := 0, 0
	for i, n := range tr.sizes {
		out = append(out, f.write(tr.in[at:at+n])...)
		held = max(held, len(f.tail))
		if at += n; tr.pauses[i] {
			out = append(out, f.flush(false)...)
			pauses = append(pauses, at)
		}
	}
	return string(append(out, f.flush(true)...)), f, append(pauses, len(tr.in)), held
}

// check explains how the trial's output fails to come out showing no secret,
// with nothing else lost, added or moved, and, without pauses, the same however
// it is split into writes. The filter must hold less than its longest secret.
func check(tr trial) error {
	// Making the patterns is much of a run's work, and they serve every run.
	pats := patterns(tr.secrets, nil)
	out, f, pauses, held := tr.run(pats)
	if err := replaced(pats, tr.in, []byte(out), pauses, f.masked); err != nil {
		return fmt.Errorf("%v\n%v\noutput %q", err, tr, out)
	}
	if held > 0 && held >= f.longest {
		return fmt.Errorf("held %d bytes, and the longest secret is %d\n%v", held, f.longest, tr)
	}
	whole, wf, _, _ := trial{secrets: tr.secrets, in: tr.in, sizes: []int{len(tr.in)}, pauses: []bool{false}}.run(pats)
	split := tr
	split.pauses = make([]bool, len(tr.pauses))
	if got, sf, _, _ := split.run(pats); got != whole || !maps.Equal(sf.masked, wf.masked) {
		return fmt.Errorf("split without pauses, output %q, masked %v; whole %q, masked %v\n%v", got, sf.masked, whole, wf.masked, tr)
	}
	return nil
}

var placeholders = regexp.MustCompile(`(?:cap://[a-z]+#masked)+`)

// armourLines matches the armour at the start of a value: a PEM block's armour
// line and its line end, as written or escaped in JSON once or twice, and in an
// OpenSSH key the next line too, if it is at most 70 characters of base64 and
// ends the same way. A label is printable ASCII other than - and \, with a
// single - or space between.
var armourLines = func() *regexp.Regexp {
	var ends []string
	for _, end := range []string{"\n", "\r\n", `\n`, `\r\n`, `\\n`, `\\r\\n`} {
		e := regexp.QuoteMeta(end)
		ends = append(ends, e+`(?:b3BlbnNzaC1rZXktdjEA[A-Za-z0-9+/=]{0,50}`+e+`)?`)
	}
	return regexp.MustCompile(`^-----BEGIN [!-,.-\[\]-~](?:[- ]?[!-,.-\[\]-~])*-----(?:` + strings.Join(ends, "|") + `)`)
}()

// armourOf returns the length of the armour that text starts with, or 0.
func armourOf(text []byte) int {
	if loc := armourLines.FindIndex(text); loc != nil {
		return loc[1]
	}
	return 0
}

// replaced explains how out fails to be in with secrets replaced: each run of
// placeholders stands for one or more bytes of in, each of them part of a
// secret, or of the start of one that a pause let go; everything else in out
// is in as written, and shows a byte of a secret only in a short start, or the
// armour the secret starts with, that the first pause after the byte let
// through. Each name masked holds is of a secret in the input, or of one whose
// start a pause gave away. No input holds a #, so none holds a placeholder.
func replaced(pats []pattern, in, out []byte, pauses []int, masked map[string]bool) error {
	hideable := make([]bool, len(in))
	// secret marks the bytes that must not go out as written, and named the
	// secrets that may be recorded.
	secret := make([]bool, len(in))
	named := map[string]bool{}
	longest := 0
	var byFirst [256][]*pattern
	armours := make([]int, len(pats))
	for i, p := range pats {
		longest = max(longest, len(p.text))
		byFirst[p.text[0]] = append(byFirst[p.text[0]], &pats[i])
		armours[i] = armourOf(p.text)
	}
	// givesAway reports whether start, the first bytes of p, is too much for a
	// pause to let through: MinLength bytes or more, or half of p, and more than
	// the armour of each pattern of p's secret that start begins, p included. It
	// is written out here, not taken from the filter, which this checks.
	givesAway := func(p *pattern, start []byte) bool {
		n := len(start)
		for i, q := range pats {
			if n <= armours[i] && q.name == p.name && len(q.text) > n && bytes.HasPrefix(q.text, start) {
				return false
			}
		}
		return n >= MinLength || 2*n >= len(p.text)
	}
	// short reports whether a pause at end may let in[s:end] through as written.
	short := func(s, end int) bool {
		for _, p := range byFirst[in[s]] {
			if len(p.text) > end-s && bytes.HasPrefix(p.text, in[s:end]) && givesAway(p, in[s:end]) {
				return false
			}
		}
		return true
	}
	for _, p := range pats {
		for s := 0; ; s++ {
			i := bytes.Index(in[s:], p.text)
			if i < 0 {
				break
			}
			s += i
			named[p.name] = true
			e, k, ok := s+len(p.text), -1, false
			for j := s; j < e; j++ {
				if k < 0 || pauses[k] <= j {
					k, _ = slices.BinarySearch(pauses, j+1)
					ok = pauses[k] < e && short(s, pauses[k])
				}
				hideable[j], secret[j] = true, secret[j] || !ok
			}
		}
	}
	// A start held at a pause that gives a secret away must not go out as
	// written, from the pause before it on, and may be recorded. Any start may go
	// if it goes on from a secret. Longer starts come later, so they see what
	// shorter ones marked.
	prev := 0
	for _, end := range pauses {
		for q := end - 1; q >= 0 && end-q < longest; q-- {
			for _, p := range byFirst[in[q]] {
				if len(p.text) <= end-q || !bytes.HasPrefix(p.text, in[q:end]) {
					continue
				}
				if givesAway(p, in[q:end]) {
					named[p.name] = true
					for j := max(q, prev); j < end; j++ {
						secret[j] = true
					}
				} else if !slices.Contains(hideable[q:end], true) {
					continue
				}
				for j := q; j < end; j++ {
					hideable[j] = true
				}
			}
		}
		prev = end
	}
	for name := range masked {
		if !named[name] {
			return fmt.Errorf("%s is recorded, but neither it nor a start of it shows", name)
		}
	}
	var pieces [][]byte
	at := 0
	for _, loc := range placeholders.FindAllIndex(out, -1) {
		pieces, at = append(pieces, out[at:loc[0]]), loc[1]
	}
	pieces = append(pieces, out[at:])
	for _, piece := range pieces {
		for _, p := range pats {
			if bytes.Contains(piece, p.text) {
				return fmt.Errorf("output shows %q", p.text)
			}
		}
	}
	// fits reports whether piece is in's bytes from at as written, and may show.
	fits := func(at int, piece []byte) (bool, error) {
		switch {
		case !bytes.HasPrefix(in[at:], piece):
			return false, nil
		case slices.Contains(secret[at:at+len(piece)], true):
			return false, fmt.Errorf("%q shows more of a secret than a pause lets through", piece)
		}
		return true, nil
	}
	// Every place in the input where the output so far can have come from.
	if ok, err := fits(0, pieces[0]); !ok {
		return cmp.Or(err, fmt.Errorf("output starts with %q", pieces[0]))
	}
	ends := make([]bool, len(in)+1)
	ends[len(pieces[0])] = true
	for _, piece := range pieces[1:] {
		// The next piece starts after one or more hidden bytes that follow an end.
		next := make([]bool, len(in)+1)
		var err error
		found, after := false, false
		for at := 1; at <= len(in); at++ {
			if after = hideable[at-1] && (after || ends[at-1]); after {
				ok, why := fits(at, piece)
				if ok {
					next[at+len(piece)], found = true, true
				}
				err = cmp.Or(err, why)
			}
		}
		if ends = next; !found {
			return cmp.Or(err, fmt.Errorf("no hidden stretch of the input comes before %q", piece))
		}
	}
	if !ends[len(in)] {
		return fmt.Errorf("output ends before the input does")
	}
	return nil
}

// The check of a trial lets output show only what a pause may let through of a
// secret: a short start, or a key's armour line, which must not be hidden, also
// as much of it as starts the key URL-encoded. Most of one beside a
// placeholder, a long start, its last few bytes, or a short start with no pause
// after it, fail, and so does a name recorded with nothing to show for it.
func TestTheCheckLetsOnlyAShortStartOfASecretShow(t *testing.T) {
	key, armour := pem("FAKE KEY", "FakeKeyLine0123456789+/xyz"), "-----BEGIN FAKE KEY-----\n"
	pats := newFilter([]Secret{{Name: "t", Value: token}, {Name: "k", Value: key}}).pats
	in, cut, keyIn, a := "x "+token+" y", "x "+token[:20], "x "+key+" y", 2+len(armour)
	urlIn := "x " + url.QueryEscape(strings.TrimSpace(key)) + " y"
	for name, tc := range map[string]struct {
		in, out string
		pauses  []int
		masked  []string
		ok      bool
	}{
		"hidden":                            {in, "x " + Placeholder("t") + " y", nil, []string{"t"}, true},
		"a short start at a pause":          {in, "x " + token[:3] + Placeholder("t") + " y", []int{5}, []string{"t"}, true},
		"all but its first byte":            {in, "x " + Placeholder("t") + token[1:] + " y", nil, []string{"t"}, false},
		"a long start at a pause":           {in, "x " + token[:20] + Placeholder("t") + " y", []int{22}, []string{"t"}, false},
		"its last few bytes":                {in, "x " + Placeholder("t") + token[35:] + " y", nil, []string{"t"}, false},
		"a short start, no pause":           {in, "x " + token[:3] + Placeholder("t") + " y", nil, []string{"t"}, false},
		"a long start at the end, hidden":   {cut, "x " + Placeholder("t"), nil, []string{"t"}, true},
		"a long start at the end":           {cut, cut, nil, nil, false},
		"a name with nothing to show":       {"x y", "x y", nil, []string{"t"}, false},
		"an armour line at a pause":         {keyIn, "x " + armour + Placeholder("k") + "\n y", []int{a}, []string{"k"}, true},
		"a start of one at the end":         {"x " + armour[:12], "x " + armour[:12], nil, nil, true},
		"an armour line at the end, hidden": {"x " + armour, "x " + Placeholder("k"), nil, []string{"k"}, false},
		"a byte past the armour at a pause": {keyIn, "x " + armour + "F" + Placeholder("k") + "\n y", []int{a + 1}, []string{"k"}, false},
		"its start URL-encoded at a pause":  {urlIn, "x -----BEGIN" + Placeholder("k") + " y", []int{12}, []string{"k"}, true},
		"a byte more of it URL-encoded":     {urlIn, "x -----BEGIN+" + Placeholder("k") + " y", []int{13}, []string{"k"}, false},
	} {
		masked := map[string]bool{}
		for _, name := range tc.masked {
			masked[name] = true
		}
		if err := replaced(pats, []byte(tc.in), []byte(tc.out), append(tc.pauses, len(tc.in)), masked); (err == nil) != tc.ok {
			t.Errorf("%s: error %v", name, err)
		}
	}
}

// units are what random secrets and output are made of: letters, a digit, and
// characters that JSON, URLs and base64 each change.
var units = []string{"a", "X", "y", "Z", "q", "W", "7", `"`, `\`, "/", " ", "+", "%", "<", "é", "~", ":"}

// text returns n random units.
func text(r *rand.Rand, n int) string {
	var b strings.Builder
	for range n {
		b.WriteString(units[r.IntN(len(units))])
	}
	return b.String()
}

// keyText returns n random characters of base64, which a key's lines are made of.
func keyText(r *rand.Rand, n int) string {
	const chars = "aXyZqW7+/="
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.IntN(len(chars))]
	}
	return string(b)
}

// randomTrial makes secrets that share a start, overlap one another or
// themselves, or span lines, and output of whole and partial forms of them
// among other text, written in pieces of random sizes with random pauses.
func randomTrial(r *rand.Rand) trial {
	var tr trial
	for i := range 1 + r.IntN(3) {
		other := ""
		if i > 0 {
			other = tr.secrets[r.IntN(i)].Value
		}
		var v string
		switch k := r.IntN(7); {
		case k == 1 && other != "":
			v = other[:r.IntN(len(other))] + text(r, 4+r.IntN(8))
		case k == 2 && other != "":
			v = other[r.IntN(len(other)):] + text(r, 4+r.IntN(8))
		case k == 3:
			v = strings.Repeat(units[r.IntN(7)], 2+r.IntN(10)) + text(r, r.IntN(6))
		case k == 4:
			u := units[r.IntN(len(units))]
			v = u + text(r, 6+r.IntN(4)) + u
		case k == 5:
			lines := []string{keyText(r, 12+r.IntN(10)), keyText(r, 12+r.IntN(10)), keyText(r, 2+r.IntN(4))}
			if r.IntN(2) == 0 {
				label := []string{"FAKE KEY", "Fake tls-crypt-v2 key", "OPENSSH PRIVATE KEY"}[r.IntN(3)]
				if label == "OPENSSH PRIVATE KEY" {
					lines[0] = "b3BlbnNzaC1rZXktdjEA" + lines[0]
				}
				lines = append([]string{"-----BEGIN " + label + "-----"}, lines...)
			}
			// The lines may be in a JSON string, as a service account key holds its key.
			v = strings.Join(lines, []string{"\n", `\n`}[r.IntN(2)])
		default:
			v = text(r, 8+r.IntN(12))
		}
		tr.secrets = append(tr.secrets, Secret{Name: string(rune('a' + i)), Value: v})
	}
	var all [][][]byte
	for _, s := range tr.secrets {
		all = append(all, forms([]byte(strings.TrimSpace(s.Value))))
	}
	var ends []int
	for range 4 + r.IntN(12) {
		ends = append(ends, len(tr.in))
		k := r.IntN(len(tr.secrets))
		v := all[k][0]
		if len(v) == 0 {
			continue
		}
		form := all[k][r.IntN(len(all[k]))]
		switch r.IntN(8) {
		case 0:
			tr.in = append(tr.in, form...)
		case 1:
			i := r.IntN(len(form) + 1)
			tr.in = append(tr.in, form[i:i+r.IntN(len(form)-i+1)]...)
		case 2:
			// The secret starts inside a start of itself.
			tr.in = append(append(tr.in, form[:r.IntN(len(form))]...), form...)
		case 3:
			// Two secrets, one's end the other's start.
			w := all[r.IntN(len(all))][0]
			overlap := 0
			for i := 1; i < min(len(v), len(w)); i++ {
				if bytes.HasSuffix(v, w[:i]) {
					overlap = i
				}
			}
			tr.in = append(append(tr.in, v...), w[overlap:]...)
		case 4:
			plain := text(r, r.IntN(4)) + string(v) + text(r, r.IntN(4))
			enc := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding}[r.IntN(3)]
			tr.in = append(tr.in, enc.EncodeToString([]byte(plain))...)
		case 5:
			tr.in = append(tr.in, bytes.Repeat(v[:1], r.IntN(24))...)
		case 6:
			// Its first line or two, as a key's armour, then its rest or other
			// output, with a pause likely between them.
			i := 0
			for range 1 + r.IntN(2) {
				next := len(form)
				for _, end := range []string{"\n", `\n`} {
					if j := bytes.Index(form[i:], []byte(end)); j >= 0 {
						next = min(next, i+j+len(end))
					}
				}
				i = next
			}
			tr.in = append(tr.in, form[:i]...)
			if r.IntN(2) == 0 {
				ends = append(ends, len(tr.in))
				tr.in = append(tr.in, form[i:]...)
			}
		default:
			tr.in = append(tr.in, text(r, 1+r.IntN(10))...)
		}
	}
	// Some trials pause often between small writes, others seldom between large.
	// A pause where one piece ends and the next begins is the likeliest to cut a
	// secret short.
	size, often := 1+r.IntN(24), 1+r.IntN(6)
	for at := 0; at < len(tr.in); {
		n, pause := min(len(tr.in)-at, 1+r.IntN(size)), r.IntN(often) == 0
		if i, _ := slices.BinarySearch(ends, at+1); i < len(ends) && ends[i] <= at+n && r.IntN(2) == 0 {
			n, pause = ends[i]-at, true
		}
		tr.sizes, tr.pauses, at = append(tr.sizes, n), append(tr.pauses, pause), at+n
	}
	return tr
}

// However output arrives, no secret shows in it, and nothing else is lost.
func TestNoSecretSurvivesAnyWritesAndPauses(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 8))
	trials := make([]trial, 1200)
	for i := range trials {
		trials[i] = randomTrial(r)
	}
	// Each trial has filters of its own, so they are checked on every core, which
	// keeps the test quick on a busy machine.
	work := make(chan int, len(trials))
	for i := range trials {
		work <- i
	}
	close(work)
	errs := make([]error, len(trials))
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for i := range work {
				errs[i] = check(trials[i])
			}
		})
	}
	wg.Wait()
	if err := cmp.Or(errs...); err != nil {
		t.Fatal(err)
	}
}

// FuzzFilter checks what TestNoSecretSurvivesAnyWritesAndPauses does, with two
// secrets and output that go test -fuzz chooses. A byte of recipe below 16 is
// a piece of a secret, any other is itself. A byte of plan is a write of up to
// 64 bytes, with a pause after it if its 0x40 bit is set.
func FuzzFilter(f *testing.F) {
	f.Add("xxxxxxyy", "", []byte("xxxxxxxyy"), []byte{0x41})
	f.Add("1111aaaa2222", "aaaa2222bbbb3333", []byte("<1111aaaa2222bbbb3333>"), []byte{0x44})
	f.Add("sk_"+"live_FakeAAAA0123456789", "sk_"+"live_FakeBBBB0123456789", []byte("key: sk_"+"live_FakeBBBB0123456789\n"), []byte{0x50})
	f.Add("aaaaaaaaaa", "aXyZqW7a", []byte("aaaaaaaaaaaaaaaaaaaaa\x08XyZqW7aXyZqW7a\x0f"), []byte{0x46, 0x4d, 3})
	f.Add("Fake\"pass/w\\rd é<", "LineOneOfAFakeKey0+\nLineTwoOfAFakeKey1/", []byte("\x03\x0b{\x0e\x00}\x09\x0c\x0d"), []byte{0x45, 0x48, 0x02})
	f.Add("-----BEGIN FAKE KEY-----\nFakeKeyLine0123+/xyz\n-----END FAKE KEY-----", "", []byte("\x05OtherFakeKeyLine99\x00"), []byte{0x58, 0x51, 0x58})
	f.Fuzz(func(t *testing.T, a, b string, recipe, plan []byte) {
		// A # could make a placeholder, and the check could not tell it apart.
		clean := func(s string) string { return strings.ReplaceAll(s, "#", ".") }
		tr := trial{secrets: []Secret{{Name: "a", Value: clean(a)}, {Name: "b", Value: clean(b)}}}
		// Long recipes only slow the search down.
		for i, c := range recipe[:min(len(recipe), 256)] {
			v := []byte(strings.TrimSpace(tr.secrets[c>>3&1].Value))
			switch {
			case c == '#':
				tr.in = append(tr.in, '.')
			case c >= 16:
				tr.in = append(tr.in, c)
			case len(v) == 0:
			case c&7 == 0:
				tr.in = append(tr.in, v...)
			case c&7 == 1:
				tr.in = append(tr.in, v[:len(v)/2]...)
			case c&7 == 2:
				tr.in = append(tr.in, v[len(v)/2:]...)
			case c&7 == 3:
				all := forms(v)
				tr.in = append(tr.in, all[i%len(all)]...)
			case c&7 == 4:
				tr.in = append(tr.in, base64.StdEncoding.EncodeToString(v)...)
			case c&7 == 5:
				// Its first line, as a key's armour line.
				tr.in = append(tr.in, v[:bytes.IndexByte(v, '\n')+1]...)
			case c&7 == 6:
				tr.in = append(tr.in, v[1:]...)
			default:
				tr.in = append(tr.in, bytes.Repeat(v[:1], 20)...)
			}
		}
		for at, i := 0, 0; at < len(tr.in); i++ {
			n, pause := len(tr.in)-at, false
			if i < len(plan) {
				n, pause = min(n, 1+int(plan[i]&63)), plan[i]&0x40 != 0
			}
			tr.sizes, tr.pauses, at = append(tr.sizes, n), append(tr.pauses, pause), at+n
		}
		if err := check(tr); err != nil {
			t.Fatal(err)
		}
	})
}
