//go:build darwin && cgo

package vault

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// The CoreFoundation plumbing lives here rather than in Go on purpose.
//
// cgo maps these types inconsistently on macOS — CFTypeRef and CFStringRef
// become uintptr while CFMutableDictionaryRef becomes a pointer — so bridging
// them in Go needs unsafe.Pointer conversions that go vet flags and that would
// silently change with an SDK update. In C they are just themselves.
//
// Reference counting is also simpler here: a CF dictionary created with
// kCFTypeDictionaryValueCallBacks retains what it is given, so each value can be
// released immediately after insertion and there is no ownership to track.

// kw_query builds the dictionary identifying generic-password items for a
// service, optionally narrowed to one account. Returns NULL on failure, which
// callers must treat as fatal — a query missing its service attribute would
// match items belonging to something else.
static CFMutableDictionaryRef kw_query(const char *service, const char *account) {
	CFMutableDictionaryRef q = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!q) return NULL;

	CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);

	CFStringRef svc = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	if (!svc) { CFRelease(q); return NULL; }
	CFDictionarySetValue(q, kSecAttrService, svc);
	CFRelease(svc);

	if (account) {
		CFStringRef acct = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
		if (!acct) { CFRelease(q); return NULL; }
		CFDictionarySetValue(q, kSecAttrAccount, acct);
		CFRelease(acct);
	}
	return q;
}

// kw_get copies the stored value into *out (malloc'd; release with
// kw_free_secure).
static OSStatus kw_get(const char *service, const char *account, void **out, int *outLen) {
	*out = NULL;
	*outLen = 0;

	CFMutableDictionaryRef q = kw_query(service, account);
	if (!q) return errSecAllocate;
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
	CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);

	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st != errSecSuccess) return st;
	if (!result) return errSecItemNotFound;

	CFDataRef data = (CFDataRef)result;
	CFIndex n = CFDataGetLength(data);
	if (n > 0) {
		void *buf = malloc((size_t)n);
		if (!buf) { CFRelease(result); return errSecAllocate; }
		memcpy(buf, CFDataGetBytePtr(data), (size_t)n);
		*out = buf;
		*outLen = (int)n;
	}
	CFRelease(result);
	return errSecSuccess;
}

// kw_put adds a new item. SecItemAdd reports errSecDuplicateItem if the account
// already exists, which is what gives Put its never-overwrite behaviour.
// kw_set_note attaches provenance. A NULL or empty note is simply not set.
static void kw_set_note(CFMutableDictionaryRef d, const char *note) {
	if (!note || !*note) return;
	CFStringRef s = CFStringCreateWithCString(kCFAllocatorDefault, note, kCFStringEncodingUTF8);
	if (!s) return;
	CFDictionarySetValue(d, kSecAttrComment, s);
	CFRelease(s);
}

static OSStatus kw_put(const char *service, const char *account, const void *val, int valLen, const char *note) {
	CFMutableDictionaryRef q = kw_query(service, account);
	if (!q) return errSecAllocate;

	CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)val, (CFIndex)valLen);
	if (!data) { CFRelease(q); return errSecAllocate; }
	CFDictionarySetValue(q, kSecValueData, data);
	CFRelease(data);
	kw_set_note(q, note);

	OSStatus st = SecItemAdd(q, NULL);
	CFRelease(q);
	return st;
}

// kw_update overwrites an existing item, reporting errSecItemNotFound if absent.
static OSStatus kw_update(const char *service, const char *account, const void *val, int valLen, const char *note) {
	CFMutableDictionaryRef q = kw_query(service, account);
	if (!q) return errSecAllocate;

	CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
		kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (!attrs) { CFRelease(q); return errSecAllocate; }

	CFDataRef data = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)val, (CFIndex)valLen);
	if (!data) { CFRelease(attrs); CFRelease(q); return errSecAllocate; }
	CFDictionarySetValue(attrs, kSecValueData, data);
	CFRelease(data);
	// Always set the comment, so replacing a value clears stale provenance rather
	// than leaving a note pointing at the wrong file.
	CFStringRef noteStr = CFStringCreateWithCString(kCFAllocatorDefault, note ? note : "", kCFStringEncodingUTF8);
	if (noteStr) { CFDictionarySetValue(attrs, kSecAttrComment, noteStr); CFRelease(noteStr); }

	OSStatus st = SecItemUpdate(q, attrs);
	CFRelease(attrs);
	CFRelease(q);
	return st;
}

static OSStatus kw_delete(const char *service, const char *account) {
	CFMutableDictionaryRef q = kw_query(service, account);
	if (!q) return errSecAllocate;
	OSStatus st = SecItemDelete(q);
	CFRelease(q);
	return st;
}

// kw_list writes one record per item into *out (malloc'd; release with free), as
// "account\x1fnote" separated by newlines.
//
// Both separators are safe: handle.Normalize rejects a name containing either, and
// SanitizeNote replaces them in notes before they are stored.
static OSStatus kw_list(const char *service, char **out) {
	*out = NULL;

	CFMutableDictionaryRef q = kw_query(service, NULL);
	if (!q) return errSecAllocate;
	CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitAll);
	CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);

	CFTypeRef result = NULL;
	OSStatus st = SecItemCopyMatching(q, &result);
	CFRelease(q);
	if (st != errSecSuccess) return st;
	if (!result) { *out = strdup(""); return *out ? errSecSuccess : errSecAllocate; }

	CFMutableStringRef joined = CFStringCreateMutable(kCFAllocatorDefault, 0);
	if (!joined) { CFRelease(result); return errSecAllocate; }

	CFArrayRef items = (CFArrayRef)result;
	CFIndex n = CFArrayGetCount(items);
	for (CFIndex i = 0; i < n; i++) {
		CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(items, i);
		if (!item) continue;
		CFStringRef acct = (CFStringRef)CFDictionaryGetValue(item, kSecAttrAccount);
		if (!acct) continue;
		CFStringAppend(joined, acct);
		CFStringAppendCString(joined, "\x1f", kCFStringEncodingUTF8);
		CFStringRef note = (CFStringRef)CFDictionaryGetValue(item, kSecAttrComment);
		if (note) CFStringAppend(joined, note);
		CFStringAppendCString(joined, "\n", kCFStringEncodingUTF8);
	}
	CFRelease(result);

	CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(joined), kCFStringEncodingUTF8) + 1;
	char *buf = malloc((size_t)max);
	if (!buf) { CFRelease(joined); return errSecAllocate; }
	if (!CFStringGetCString(joined, buf, max, kCFStringEncodingUTF8)) {
		free(buf);
		CFRelease(joined);
		return errSecDecode;
	}
	CFRelease(joined);
	*out = buf;
	return errSecSuccess;
}

// kw_free_secure zeroes a buffer before releasing it, so a value does not linger
// in freed heap memory any longer than necessary.
static void kw_free_secure(void *p, int len) {
	if (!p) return;
	memset(p, 0, (size_t)len);
	free(p);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

// keychainMu serialises every SecItem call in this process.
//
// The legacy file-based keychain is not safe for concurrent enumeration and
// mutation. Running the contract suite's concurrency case against it produced
// OSStatus -67701, errSecInvalidRecord: SecItemCopyMatching with
// kSecMatchLimitAll walks the records while another thread adds or deletes one,
// and trips over an entry that is no longer there.
//
// The lock is package scoped rather than per-store because the keychain file is a
// single shared resource — two Keychain values in one process address the same
// store and would otherwise still race.
//
// This does not order operations across processes. Two keyward processes mutating
// and listing at the same moment can still collide; that is rarer, and recorded
// in doc/obstacles.md rather than papered over here.
var keychainMu sync.Mutex

// Keychain stores secrets as generic passwords in the macOS Keychain.
//
// This is the one layer that cannot be unit tested: it touches live OS state and
// may prompt. It is kept as thin as possible — name validation, value handling,
// and status mapping all live in pure Go — and its behaviour is verified by
// running the same contract suite the in-memory fake passes. See
// keychain_integration_test.go.
//
// Items go to the default file-based keychain. The data protection keychain is
// deliberately not requested: an unsigned binary cannot use it without an
// entitlement, which is a problem for any future biometric work rather than a
// problem for basic storage.
type Keychain struct {
	service string
}

// NewKeychain returns a store using DefaultService.
func NewKeychain() *Keychain {
	return &Keychain{service: DefaultService}
}

// NewKeychainService returns a store scoped to an explicit service name, which is
// how tests stay isolated from real entries.
func NewKeychainService(service string) *Keychain {
	return &Keychain{service: service}
}

var errEmptyService = errors.New("vault: keychain service name is empty")

// Get implements Store.
func (k *Keychain) Get(name string) (Secret, error) {
	key, err := k.resolve(name)
	if err != nil {
		return Secret{}, err
	}

	svc, acct, free := k.cStrings(key)
	defer free()

	keychainMu.Lock()
	var buf unsafe.Pointer
	var n C.int
	status := C.kw_get(svc, acct, &buf, &n)
	keychainMu.Unlock()
	if err := statusError("get", key, int32(status)); err != nil {
		return Secret{}, err
	}
	if buf == nil || n == 0 {
		// Cannot happen through this package, since Put rejects empty values.
		return Secret{}, fmt.Errorf("keychain get %q: stored item has no value", key)
	}
	defer C.kw_free_secure(buf, n)

	b := C.GoBytes(buf, n)
	secret := NewSecret(b)
	// NewSecret copied; clear the intermediate so only one copy survives.
	for i := range b {
		b[i] = 0
	}
	return secret, nil
}

// Put implements Store.
func (k *Keychain) Put(name string, value Secret, note string) error {
	key, err := k.resolveWith(name, value)
	if err != nil {
		return err
	}

	svc, acct, free := k.cStrings(key)
	defer free()
	cNote := C.CString(SanitizeNote(note))
	defer C.free(unsafe.Pointer(cNote))

	b := value.Bytes()
	keychainMu.Lock()
	status := C.kw_put(svc, acct, unsafe.Pointer(&b[0]), C.int(len(b)), cNote)
	keychainMu.Unlock()
	return statusError("put", key, int32(status))
}

// Replace implements Store.
func (k *Keychain) Replace(name string, value Secret, note string) error {
	key, err := k.resolveWith(name, value)
	if err != nil {
		return err
	}

	svc, acct, free := k.cStrings(key)
	defer free()
	cNote := C.CString(SanitizeNote(note))
	defer C.free(unsafe.Pointer(cNote))

	b := value.Bytes()
	keychainMu.Lock()
	status := C.kw_update(svc, acct, unsafe.Pointer(&b[0]), C.int(len(b)), cNote)
	keychainMu.Unlock()
	return statusError("replace", key, int32(status))
}

// Delete implements Store.
func (k *Keychain) Delete(name string) error {
	key, err := k.resolve(name)
	if err != nil {
		return err
	}

	svc, acct, free := k.cStrings(key)
	defer free()

	keychainMu.Lock()
	status := C.kw_delete(svc, acct)
	keychainMu.Unlock()
	return statusError("delete", key, int32(status))
}

// Entries implements Store. Scoped to this store's service, so it never reports
// items belonging to anything else.
func (k *Keychain) Entries() ([]Entry, error) {
	if k.service == "" {
		return nil, errEmptyService
	}

	svc := C.CString(k.service)
	defer C.free(unsafe.Pointer(svc))

	keychainMu.Lock()
	var joined *C.char
	status := C.kw_list(svc, &joined)
	keychainMu.Unlock()
	// No items for this service is an empty list, not a failure.
	if int32(status) == statusItemNotFound {
		return []Entry{}, nil
	}
	if err := statusError("list", k.service, int32(status)); err != nil {
		return nil, err
	}
	if joined == nil {
		return []Entry{}, nil
	}
	defer C.free(unsafe.Pointer(joined))

	entries := make([]Entry, 0, 8)
	for _, record := range strings.Split(C.GoString(joined), "\n") {
		if record == "" {
			continue
		}
		name, note, _ := strings.Cut(record, string(noteSeparator))
		entries = append(entries, Entry{Name: name, Note: note})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// resolve normalises a name and checks the store is usable.
func (k *Keychain) resolve(name string) (string, error) {
	key, err := normalize(name)
	if err != nil {
		return "", err
	}
	if k.service == "" {
		return "", errEmptyService
	}
	return key, nil
}

// resolveWith additionally rejects an empty value, matching Memory so both
// implementations accept exactly the same inputs.
func (k *Keychain) resolveWith(name string, value Secret) (string, error) {
	key, err := checkPut(name, value)
	if err != nil {
		return "", err
	}
	if k.service == "" {
		return "", errEmptyService
	}
	return key, nil
}

// cStrings converts the service and account for the C helpers, returning a single
// function that frees both.
func (k *Keychain) cStrings(account string) (svc, acct *C.char, free func()) {
	svc = C.CString(k.service)
	acct = C.CString(account)
	return svc, acct, func() {
		C.free(unsafe.Pointer(svc))
		C.free(unsafe.Pointer(acct))
	}
}
