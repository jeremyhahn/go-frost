//go:build linux

package keystore

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ristretto255"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// TestSeal_LeavesNoPlaintextInOrdinaryMemory is the behavioral half of the
// protected-memory guarantee, and the reason this package serializes key
// packages itself instead of handing them to encoding/json.
//
// It runs a share through the whole serialization boundary - seal, then open -
// destroys every protected object involved, and then searches the process's
// writable anonymous memory for the share and for its base64 encoding. Once
// everything protected has been destroyed, a hit can only be an unprotected
// copy left behind on the ordinary heap, where it cannot be zeroized and can
// be swapped to disk.
//
// encoding/json fails this test. json.Marshal assembles its output in a buffer
// it takes from a package-level sync.Pool and returns to that pool with the
// plaintext still in it, so the base64 share survives in memory this package
// cannot reach - which is what the protected boundary replaced.
func TestSeal_LeavesNoPlaintextInOrdinaryMemory(t *testing.T) {
	// A share long enough that a match cannot be chance, and random so that no
	// earlier test can have left the same bytes behind.
	share := heapNeedle(t, 1024)

	// The base64 form the document carries, built once into a slice of its own
	// so that the test's own needle is a single stable allocation.
	encodedShare := make([]byte, base64.StdEncoding.EncodedLen(len(share)))
	base64.StdEncoding.Encode(encodedShare, share)
	needleSink = encodedShare

	needles := []struct {
		name  string
		bytes []byte
	}{
		{name: "raw share", bytes: share},
		{name: "base64 share", bytes: encodedShare},
	}
	var exclude []addressRange

	func() {
		// NewSecretBytes zeroizes the slice it seals, so hand it a copy.
		sealed := make([]byte, len(share))
		copy(sealed, share)
		exclude = append(exclude, rangeOf(sealed))

		storedKP := &StoredKeyPackage{
			Identifier:           7,
			SecretShareProtected: secmem.NewSecretBytes(sealed),
			GroupPublicKey:       []byte{5, 6, 7},
			Metadata:             KeyMetadata{KeyID: "k", GroupID: "g", Tags: map[string]string{}},
		}
		defer storedKP.Zeroize()

		payload, err := storedKP.Seal()
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		defer payload.Destroy()

		decoded, err := OpenStoredKeyPackage(payload)
		if err != nil {
			t.Fatalf("OpenStoredKeyPackage failed: %v", err)
		}
		defer decoded.Zeroize()

		if decoded.SecretShareProtected.Size() != len(share) {
			t.Fatalf("round-tripped share is %d bytes, want %d",
				decoded.SecretShareProtected.Size(), len(share))
		}
	}()

	// Nothing protected is left. Any remaining copy is on the ordinary heap.
	runtime.GC()

	for _, needle := range needles {
		if addr, found := findInProcessMemory(t, needle.bytes, exclude); found {
			t.Errorf("the %s is still in ordinary process memory at 0x%x after every "+
				"protected object was destroyed; serialization left an unprotected copy",
				needle.name, addr)
		}
	}
}

// TestSeal_ResidueScanDetectsAnUnprotectedCopy is the control for
// TestSeal_LeavesNoPlaintextInOrdinaryMemory. It runs the same share through
// encoding/json the way this package used to, and requires the scan to find
// the result. Without it, a scan that silently found nothing - because it was
// looking in the wrong place, or because the needle was wrong - would read as
// a pass.
func TestSeal_ResidueScanDetectsAnUnprotectedCopy(t *testing.T) {
	share := heapNeedle(t, 1024)

	encodedShare := make([]byte, base64.StdEncoding.EncodedLen(len(share)))
	base64.StdEncoding.Encode(encodedShare, share)
	needleSink = encodedShare

	exclude := []addressRange{rangeOf(share)}

	func() {
		// What the marshal path did before: the share copied into a wire
		// struct and handed to encoding/json. Zeroizing every slice this code
		// owns is not enough - encoding/json keeps its own.
		aux := struct{ SecretShare []byte }{SecretShare: make([]byte, len(share))}
		copy(aux.SecretShare, share)
		exclude = append(exclude, rangeOf(aux.SecretShare))

		document, err := json.Marshal(&aux)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		exclude = append(exclude, rangeOf(document))

		secmem.ZeroBytes(aux.SecretShare)
		secmem.ZeroBytes(document)
	}()

	runtime.GC()

	if _, found := findInProcessMemory(t, encodedShare, exclude); !found {
		t.Error("the residue scan did not find the copy encoding/json left behind; " +
			"the scan is not proving anything")
	}
}

// needleSink is what makes heapNeedle's allocations escape.
var needleSink []byte

// heapNeedle returns n random bytes whose address will not change.
//
// The heap is what makes it stable. A slice that stays on the goroutine stack
// moves when that stack grows, because Go grows a stack by copying it, and a
// needle that moves breaks the scan twice over: the address range excluded for
// it goes stale, and a copy of it is left behind at the address it came from.
// The scan then reports the needle as its own finding - a false positive whose
// appearance depends on how much allocation happened first, which is to say it
// looks exactly like a flaky test.
func heapNeedle(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate a %d-byte needle: %v", n, err)
	}
	needleSink = b

	return b
}

// heapNeedleFrom returns a stable heap copy of b, for a needle whose content
// the test does not get to choose. See heapNeedle for why the heap matters.
func heapNeedleFrom(t *testing.T, b []byte) []byte {
	t.Helper()

	if len(b) == 0 {
		t.Fatal("cannot build a needle from no bytes")
	}
	needle := make([]byte, len(b))
	copy(needle, b)
	needleSink = needle

	return needle
}

// addressRange is a half-open span of this process's address space.
type addressRange struct {
	start, end uint64
}

// rangeOf returns the span a slice's backing array occupies.
func rangeOf(b []byte) addressRange {
	if cap(b) == 0 {
		return addressRange{}
	}
	start := uint64(uintptr(unsafe.Pointer(&b[:1][0]))) // #nosec G103 -- test-only: excluding the test's own needles from a memory scan
	return addressRange{start: start, end: start + uint64(cap(b))}
}

func (r addressRange) contains(addr uint64) bool {
	return r.start != 0 && addr >= r.start && addr < r.end
}

// findInProcessMemory searches this process's writable anonymous mappings for
// needle, ignoring any match inside one of the excluded spans, and returns the
// address of the first hit.
//
// Only anonymous mappings are searched: that is where the Go heap, goroutine
// stacks and every ordinary allocation live. memguard's protected buffers are
// anonymous too, which is the point - a share still readable there after its
// SecretBytes was destroyed would be just as much a finding.
func findInProcessMemory(t *testing.T, needle []byte, exclude []addressRange) (uint64, bool) {
	t.Helper()

	if len(needle) == 0 {
		t.Fatal("cannot scan for an empty needle")
	}

	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatalf("failed to open /proc/self/mem: %v", err)
	}
	defer func() { _ = mem.Close() }()

	// Every region is scanned whole, in bounded chunks that overlap by enough
	// to catch a needle straddling a chunk boundary. Skipping a region on size
	// would let the scan quietly stop covering the heap it exists to search.
	const chunkSize = 1 << 20

	buf := make([]byte, chunkSize+len(needle)-1)

	// Two ranges the scan must never report, both computed here rather than
	// taken from the caller so that neither can have gone stale:
	//
	//   - the needle itself. A match at its own address is the needle, not a
	//     copy of it.
	//   - buf, which holds a copy of the window the scan read last. Once the
	//     scan reaches the region buf lives in, that copy looks exactly like a
	//     residue. Excluding it hides nothing: a genuine residue in a region
	//     scanned before buf's is found at its own address first, and one in a
	//     region scanned after has not been read into buf yet.
	exclude = append(append([]addressRange(nil), exclude...), rangeOf(needle), rangeOf(buf))

	for _, region := range writableAnonymousRegions(t) {
		for offset := region.start; offset < region.end; offset += chunkSize {
			end := offset + uint64(len(buf))
			if end > region.end {
				end = region.end
			}
			window := buf[:end-offset]

			// A mapping can be torn down between reading the map and reading
			// the memory; a failed read is not a finding. Skip only the chunk
			// that failed rather than abandoning the rest of the region: a
			// residue living past a torn-down page would otherwise go unseen,
			// and a scan that quietly stops covering memory is how this test
			// would come to pass without proving anything.
			if _, err := mem.ReadAt(window, int64(offset)); err != nil {
				continue
			}

			for searched := 0; ; {
				i := bytes.Index(window[searched:], needle)
				if i < 0 {
					break
				}
				addr := offset + uint64(searched+i)
				if !excluded(addr, exclude) {
					return addr, true
				}
				searched += i + 1
			}
		}
	}

	return 0, false
}

func excluded(addr uint64, exclude []addressRange) bool {
	for _, r := range exclude {
		if r.contains(addr) {
			return true
		}
	}
	return false
}

// writableAnonymousRegions returns this process's writable private mappings
// that are not backed by a file.
func writableAnonymousRegions(t *testing.T) []addressRange {
	t.Helper()

	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Fatalf("failed to open /proc/self/maps: %v", err)
	}
	defer func() { _ = maps.Close() }()

	var regions []addressRange

	scanner := bufio.NewScanner(maps)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for scanner.Scan() {
		// address perms offset dev inode [pathname]
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		perms := fields[1]
		if len(perms) < 4 || perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p' {
			continue
		}
		// Skip file-backed mappings - the binary's own data, not allocations.
		// An anonymous mapping either has no pathname at all or a bracketed
		// name: "[heap]", "[stack]", or a kernel VMA name such as
		// "[anon: Go: heap]", which is how the Go runtime labels the regions
		// the allocator hands out.
		if len(fields) > 5 && strings.HasPrefix(fields[5], "/") {
			continue
		}

		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, err := strconv.ParseUint(bounds[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(bounds[1], 16, 64)
		if err != nil || end <= start {
			continue
		}

		regions = append(regions, addressRange{start: start, end: end})
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("failed to read /proc/self/maps: %v", err)
	}
	if len(regions) == 0 {
		t.Fatal("found no writable anonymous mappings; the scan would prove nothing")
	}

	return regions
}

// TestMemoryStorage_LegacyReadLeavesNoPlaintext is the behavioral proof that
// reading a legacy plain value through GetSecret moves it into protected
// memory rather than copying it out.
//
// The structural half lives in TestMemoryStorage_GetSecret_PromotesPlainValue,
// which asserts the backend no longer holds the key. Removal from the map is
// not the whole property though: a removed entry's []byte keeps its contents
// until the allocator reuses it, so this scans for the value itself once every
// protected object is destroyed. Nothing may remain.
func TestMemoryStorage_LegacyReadLeavesNoPlaintext(t *testing.T) {
	// Random and long enough that a match cannot be chance.
	needle := heapNeedle(t, 1024)

	const key = "frost/keypackages/legacy.json"

	func() {
		store := NewMemoryStorage()
		defer store.Close()

		// Put copies into the backend, so the copy handed in here is the
		// test's own and is zeroized straight away: whatever the scan finds
		// afterwards belongs to the storage layer, not to this function.
		written := make([]byte, len(needle))
		copy(written, needle)
		if err := store.Put(key, written, nil); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		secmem.ZeroBytes(written)

		secret, err := store.GetSecret(key)
		if err != nil {
			t.Fatalf("GetSecret failed: %v", err)
		}
		if secret.Size() != len(needle) {
			t.Fatalf("promoted secret is %d bytes, want %d", secret.Size(), len(needle))
		}
		secret.Destroy()
	}()

	// Close destroyed the promoted enclave. Any copy still readable is one the
	// storage layer left on the ordinary heap.
	runtime.GC()

	if addr, found := findInProcessMemory(t, needle, nil); found {
		t.Errorf("the legacy value is still in ordinary process memory at 0x%x after the store was "+
			"closed; reading it through GetSecret copied it out instead of moving it", addr)
	}
}

// TestMemoryStorage_OverwriteLeavesNoPlaintext covers the overwrite sibling of
// the promotion path: a key written through the plain Put path and then
// replaced by PutSecret.
//
// The promotion path moves the value out of the backend; this one drops it,
// and dropping is where a plaintext copy is easiest to leave behind. Removing
// the map reference does not touch the bytes, so the serialized key package
// the key used to hold would stay readable in the heap for the rest of the
// process's life even though the key now holds protected material.
func TestMemoryStorage_OverwriteLeavesNoPlaintext(t *testing.T) {
	needle := heapNeedle(t, 1024)

	const key = "frost/keypackages/overwritten.json"

	func() {
		store := NewMemoryStorage()
		defer store.Close()

		// Put copies into the backend; the copy handed in here is the test's
		// own and is zeroized straight away, so whatever the scan finds
		// afterwards belongs to the storage layer.
		written := make([]byte, len(needle))
		copy(written, needle)
		if err := store.Put(key, written, nil); err != nil {
			t.Fatalf("Put failed: %v", err)
		}
		secmem.ZeroBytes(written)

		replacement := secmem.NewSecretBytes([]byte("the protected replacement"))
		defer replacement.Destroy()

		if err := store.PutSecret(key, replacement, nil); err != nil {
			t.Fatalf("PutSecret failed: %v", err)
		}

		// The key holds the replacement now, not what Put left.
		data, err := store.Get(key)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		if string(data) != "the protected replacement" {
			t.Fatalf("Get returned %q after the overwrite", data)
		}
		secmem.ZeroBytes(data)
	}()

	runtime.GC()

	if addr, found := findInProcessMemory(t, needle, nil); found {
		t.Errorf("the overwritten plain value is still in ordinary process memory at 0x%x; "+
			"PutSecret dropped the backend's entry without zeroizing what it held", addr)
	}
}

// TestFromKeyPackage_LeavesNoPlaintextShare holds the bound on the one
// protected-memory window this package cannot close.
//
// Serializing a scalar allocates the raw share on the ordinary heap, because
// that is the only thing the scalar implementations can hand back - none of
// the dependencies behind them export an encoding that fills a destination the
// caller provides. FromKeyPackage documents the boundary in full.
//
// What can be held is that the allocation does not outlive the call: it goes
// straight into NewSecretBytes, which copies it into mlock'd memory and
// zeroizes the transient in place. This scans process memory for the share
// afterwards and requires it to be gone. The in-flight window remains, and no
// test can remove it; a copy that survived the call would be a different and
// fixable defect, and this is what would catch it.
func TestFromKeyPackage_LeavesNoPlaintextShare(t *testing.T) {
	g := ristretto255.NewGroup()

	scalar, err := g.RandomScalar()
	if err != nil {
		t.Fatalf("failed to generate a share: %v", err)
	}

	// Reading the share to build the needle costs a transient of its own,
	// which is zeroized straight away so that the test's own bookkeeping is
	// not what the scan finds.
	transient := scalar.Bytes()
	needle := heapNeedleFrom(t, transient)
	secmem.ZeroBytes(transient)

	func() {
		kp := &frost.KeyPackage{
			Identifier:     1,
			SecretShare:    scalar,
			GroupPublicKey: g.Generator(),
		}

		stored, err := FromKeyPackage("key-1", "group-1", kp, 2, 3, 1000)
		if err != nil {
			t.Fatalf("FromKeyPackage failed: %v", err)
		}
		defer stored.Zeroize()

		if stored.SecretShareProtected.Size() != len(needle) {
			t.Fatalf("protected share is %d bytes, want %d",
				stored.SecretShareProtected.Size(), len(needle))
		}
	}()

	scalar.Zeroize()
	runtime.GC()

	if addr, found := findInProcessMemory(t, needle, nil); found {
		t.Errorf("the raw secret share is still in ordinary process memory at 0x%x after "+
			"FromKeyPackage returned; the serialized transient outlived the call that sealed it", addr)
	}
}
