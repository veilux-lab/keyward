//go:build darwin && cgo

package clipboard

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework AppKit
#import <AppKit/AppKit.h>

// kw_copy replaces the general pasteboard's contents with len bytes of UTF-8
// text and stores the change count in *count. Returns 0 if the pasteboard
// refused it.
static int kw_copy(const void *bytes, int len, long *count) {
	@autoreleasepool {
		NSPasteboardItem *item = [[NSPasteboardItem alloc] init];
		// The nspasteboard.org markers, which ask clipboard managers not to keep it.
		if (![item setData:[NSData dataWithBytes:bytes length:(NSUInteger)len] forType:NSPasteboardTypeString] ||
			![item setData:[NSData data] forType:@"org.nspasteboard.ConcealedType"] ||
			![item setData:[NSData data] forType:@"org.nspasteboard.TransientType"]) {
			return 0;
		}
		NSPasteboard *pb = [NSPasteboard generalPasteboard];
		// This Mac only, so Universal Clipboard does not send it to other devices.
		[pb prepareForNewContentsWithOptions:NSPasteboardContentsCurrentHostOnly];
		if (![pb writeObjects:@[item]]) {
			return 0;
		}
		*count = (long)[pb changeCount];
		return 1;
	}
}

static long kw_change_count(void) {
	@autoreleasepool {
		return (long)[[NSPasteboard generalPasteboard] changeCount];
	}
}

static void kw_clear(void) {
	@autoreleasepool {
		[[NSPasteboard generalPasteboard] clearContents];
	}
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

// Copy puts value, which must be UTF-8, on the clipboard and returns the change
// count it left there. The value reaches C in memory that is zeroed and freed
// straight after, which a Go string could not be.
func Copy(value []byte) (int, error) {
	buf := C.malloc(C.size_t(len(value)))
	text := unsafe.Slice((*byte)(buf), len(value))
	copy(text, value)
	defer func() {
		clear(text)
		C.free(buf)
	}()
	var count C.long
	if C.kw_copy(buf, C.int(len(value)), &count) == 0 {
		return 0, errors.New("the clipboard did not accept it")
	}
	return int(count), nil
}

// General is the clipboard every app copies to and pastes from.
type General struct{}

func (General) ChangeCount() int { return int(C.kw_change_count()) }
func (General) Clear()           { C.kw_clear() }
