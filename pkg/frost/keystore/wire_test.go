package keystore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-frost/pkg/frost"
	"github.com/jeremyhahn/go-frost/pkg/frost/group/ristretto255"
	"github.com/jeremyhahn/go-frost/pkg/secmem"
)

// goldenDocument pins the wire format byte for byte. It was produced by
// running json.Marshal against the pre-change StoredKeyPackage - the one that
// still carried the share as a plaintext SecretShare field declared after
// Identifier - so a store written by any earlier version of this package is
// exactly this shape, member order included. Seal must keep producing it and
// OpenStoredKeyPackage must keep reading it.
const goldenDocument = `{"Identifier":7,"SecretShare":"AQIDBA==",` +
	`"GroupPublicKey":"BQYH","VerificationShares":[{"Identifier":9,"VerificationKey":"CAk="}],` +
	`"Metadata":{"KeyID":"k","GroupID":"g","MinSigners":2,"MaxSigners":3,` +
	`"CreatedAt":1000,"UpdatedAt":2000,"Tags":{"env":"test"}}}`

// goldenPackage returns the stored key package goldenDocument serializes.
func goldenPackage(t *testing.T) *StoredKeyPackage {
	t.Helper()
	return &StoredKeyPackage{
		Identifier:           7,
		SecretShareProtected: secmem.NewSecretBytes([]byte{1, 2, 3, 4}),
		GroupPublicKey:       []byte{5, 6, 7},
		VerificationShares: []StoredVerificationShare{
			{Identifier: 9, VerificationKey: []byte{8, 9}},
		},
		Metadata: KeyMetadata{
			KeyID:      "k",
			GroupID:    "g",
			MinSigners: 2,
			MaxSigners: 3,
			CreatedAt:  1000,
			UpdatedAt:  2000,
			Tags:       map[string]string{"env": "test"},
		},
	}
}

// sealedDocument returns the plaintext of a sealed payload. Tests are allowed
// the heap copy that production code is not.
func sealedDocument(t *testing.T, payload *secmem.SecretBytes) []byte {
	t.Helper()
	var document []byte
	if err := secmem.WithSecret(payload, func(b []byte) error {
		document = append([]byte(nil), b...)
		return nil
	}); err != nil {
		t.Fatalf("failed to open the sealed payload: %v", err)
	}
	return document
}

// TestSeal_WireFormatUnchanged verifies the document Seal builds inside
// protected memory is byte-identical to the one encoding/json used to produce,
// so moving serialization off encoding/json did not move the wire format with
// it.
func TestSeal_WireFormatUnchanged(t *testing.T) {
	storedKP := goldenPackage(t)
	defer storedKP.Zeroize()

	payload, err := storedKP.Seal()
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}
	defer payload.Destroy()

	if got := string(sealedDocument(t, payload)); got != goldenDocument {
		t.Errorf("sealed document =\n%s\nwant\n%s", got, goldenDocument)
	}
}

// TestOpenStoredKeyPackage_ReadsGoldenDocument verifies a document in the
// pre-protected-memory wire format still decodes, share and all.
func TestOpenStoredKeyPackage_ReadsGoldenDocument(t *testing.T) {
	payload := secmem.NewSecretBytes([]byte(goldenDocument))
	defer payload.Destroy()

	storedKP, err := OpenStoredKeyPackage(payload)
	if err != nil {
		t.Fatalf("OpenStoredKeyPackage failed: %v", err)
	}
	defer storedKP.Zeroize()

	if storedKP.Identifier != 7 {
		t.Errorf("identifier = %d, want 7", storedKP.Identifier)
	}
	if !bytes.Equal(storedKP.GroupPublicKey, []byte{5, 6, 7}) {
		t.Errorf("group public key = %x, want 050607", storedKP.GroupPublicKey)
	}
	if len(storedKP.VerificationShares) != 1 || storedKP.VerificationShares[0].Identifier != 9 {
		t.Errorf("verification shares = %+v, want one share for identifier 9", storedKP.VerificationShares)
	}
	if storedKP.Metadata.KeyID != "k" || storedKP.Metadata.Tags["env"] != "test" {
		t.Errorf("metadata = %+v, want KeyID k and tag env=test", storedKP.Metadata)
	}

	if err := secmem.WithSecret(storedKP.SecretShareProtected, func(b []byte) error {
		if !bytes.Equal(b, []byte{1, 2, 3, 4}) {
			t.Errorf("decoded share = %x, want 01020304", b)
		}
		return nil
	}); err != nil {
		t.Fatalf("failed to open the decoded share: %v", err)
	}
}

// TestSealOpenRoundTrip verifies a real key package survives the protected
// serialization boundary unchanged.
func TestSealOpenRoundTrip(t *testing.T) {
	g := ristretto255.NewGroup()
	keyPackages := generateTestKeyPackages(t, g, 2, 3)
	kp := &keyPackages[0]

	storedKP, err := FromKeyPackage("key-1", "group-1", kp, 2, 3, 1000)
	if err != nil {
		t.Fatalf("FromKeyPackage failed: %v", err)
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

	if decoded.SecretShareProtected == nil {
		t.Fatal("decoded package has no protected secret share")
	}
	if got, want := decoded.SecretShareProtected.Size(), len(kp.SecretShare.Bytes()); got != want {
		t.Errorf("protected share size = %d, want %d", got, want)
	}

	restored, err := decoded.ToKeyPackage(g)
	if err != nil {
		t.Fatalf("ToKeyPackage failed: %v", err)
	}
	if !restored.SecretShare.Equal(kp.SecretShare) {
		t.Error("restored secret share does not match the original")
	}
	if restored.Identifier != kp.Identifier {
		t.Errorf("restored identifier = %d, want %d", restored.Identifier, kp.Identifier)
	}
}

// TestSeal_MissingShare verifies a package with no protected share has nothing
// to serialize and says so, rather than writing a document with an empty share
// that would later fail to convert.
func TestSeal_MissingShare(t *testing.T) {
	var nilKP *StoredKeyPackage
	if _, err := nilKP.Seal(); !errors.Is(err, ErrMissingSecretShare) {
		t.Errorf("Seal on a nil package: expected ErrMissingSecretShare, got %v", err)
	}

	storedKP := &StoredKeyPackage{Identifier: 1}
	if _, err := storedKP.Seal(); !errors.Is(err, ErrMissingSecretShare) {
		t.Errorf("Seal without a share: expected ErrMissingSecretShare, got %v", err)
	}
}

// TestSeal_DestroyedShare verifies a destroyed enclave surfaces as a typed
// protected-memory error rather than as a document with an empty share.
func TestSeal_DestroyedShare(t *testing.T) {
	storedKP := goldenPackage(t)
	storedKP.SecretShareProtected.Destroy()

	_, err := storedKP.Seal()
	if err == nil {
		t.Fatal("expected an error sealing a destroyed share")
	}
	if !errors.Is(err, secmem.ErrDestroyed) {
		t.Errorf("expected ErrDestroyed cause, got %v", err)
	}
}

// TestStoredKeyPackage_RefusesEncodingJSON verifies the type cannot be routed
// through encoding/json at all. This is the regression guard for the leak the
// protected boundary exists to close: encoding/json assembles its result in a
// pooled buffer it never zeroizes, so a StoredKeyPackage that could be
// marshaled that way would leave the share on the ordinary heap.
func TestStoredKeyPackage_RefusesEncodingJSON(t *testing.T) {
	storedKP := goldenPackage(t)
	defer storedKP.Zeroize()

	if _, err := json.Marshal(storedKP); !errors.Is(err, ErrPlaintextSerialization) {
		t.Errorf("json.Marshal: expected ErrPlaintextSerialization, got %v", err)
	}

	var decoded StoredKeyPackage
	if err := json.Unmarshal([]byte(goldenDocument), &decoded); !errors.Is(err, ErrPlaintextSerialization) {
		t.Errorf("json.Unmarshal: expected ErrPlaintextSerialization, got %v", err)
	}
	if decoded.SecretShareProtected != nil {
		t.Error("refused decode still produced a protected share")
	}
}

// TestOpenStoredKeyPackage_MissingShare verifies a document that carries no
// usable share is rejected outright. Nothing is returned, so there is no
// package that could later convert a share it never decoded.
func TestOpenStoredKeyPackage_MissingShare(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{name: "omitted share", doc: `{"Identifier":7}`},
		{name: "empty object", doc: `{}`},
		{name: "empty share", doc: `{"Identifier":7,"SecretShare":""}`},
		{name: "null share", doc: `{"Identifier":7,"SecretShare":null}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := secmem.NewSecretBytes([]byte(tt.doc))
			defer payload.Destroy()

			storedKP, err := OpenStoredKeyPackage(payload)
			if !errors.Is(err, ErrMissingSecretShare) {
				t.Fatalf("expected ErrMissingSecretShare, got %v", err)
			}
			if storedKP != nil {
				t.Error("a rejected document still produced a key package")
			}
		})
	}
}

// TestOpenStoredKeyPackage_Rejects verifies documents this package cannot
// decode safely are rejected with a typed error and no key package.
func TestOpenStoredKeyPackage_Rejects(t *testing.T) {
	share := base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})

	tests := []struct {
		name string
		doc  string
	}{
		{name: "not JSON", doc: `not a document`},
		{name: "not an object", doc: `[1,2,3]`},
		{name: "truncated", doc: `{"SecretShare":"` + share},
		{name: "share is not a string", doc: `{"SecretShare":1234,"Identifier":7}`},
		{name: "share is not base64", doc: `{"SecretShare":"not base64!!","Identifier":7}`},
		{name: "share carries an escape", doc: `{"SecretShare":"A\u0051==","Identifier":7}`},
		{name: "share twice", doc: `{"SecretShare":"` + share + `","SecretShare":"` + share + `"}`},
		{name: "share twice, second name escaped", doc: `{"SecretShare":"` + share + `","\u0053ecretShare":"` + share + `"}`},
		{name: "public field of the wrong type", doc: `{"SecretShare":"` + share + `","Identifier":"seven"}`},
		{name: "metadata of the wrong type", doc: `{"SecretShare":"` + share + `","Metadata":{"MinSigners":"two"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := secmem.NewSecretBytes([]byte(tt.doc))
			defer payload.Destroy()

			storedKP, err := OpenStoredKeyPackage(payload)
			if err == nil {
				t.Fatal("expected the document to be rejected")
			}
			var keystoreErr *KeystoreError
			if !errors.As(err, &keystoreErr) {
				t.Errorf("expected a typed keystore error, got %v", err)
			}
			if storedKP != nil {
				t.Error("a rejected document still produced a key package")
			}
		})
	}
}

// TestJSONStringMember covers the scan that locates the share inside a
// document held in protected memory - the one piece of JSON handling this
// package does itself, because encoding/json cannot hand back a member without
// copying it to the heap.
func TestJSONStringMember(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		want    string
		wantErr error
	}{
		{name: "only member", doc: `{"a":"x"}`, want: "x"},
		{name: "first of several", doc: `{"a":"x","b":"y"}`, want: "x"},
		{name: "last of several", doc: `{"b":"y","a":"x"}`, want: "x"},
		{name: "empty value", doc: `{"a":""}`, want: ""},
		{name: "null value", doc: `{"a":null,"b":1}`, want: ""},
		{name: "whitespace everywhere", doc: "{ \n\t\"b\" : 1 ,\r\n \"a\" : \"x\" }", want: "x"},
		{name: "after nested object", doc: `{"b":{"a":"decoy"},"a":"x"}`, want: "x"},
		{name: "after nested array", doc: `{"b":[{"a":"decoy"},[1,2]],"a":"x"}`, want: "x"},
		{name: "after brace inside a string", doc: `{"b":"}{\"a\":\"decoy\"","a":"x"}`, want: "x"},
		{name: "after an escaped quote", doc: `{"b":"\"","a":"x"}`, want: "x"},
		{name: "after literals", doc: `{"b":null,"c":true,"d":-1.5e3,"a":"x"}`, want: "x"},
		{name: "nested member is not the top-level one", doc: `{"b":{"a":"decoy"}}`, wantErr: errJSONMemberMissing},
		{name: "member absent", doc: `{"b":"y"}`, wantErr: errJSONMemberMissing},
		{name: "empty object", doc: `{}`, wantErr: errJSONMemberMissing},
		{name: "value is a number", doc: `{"a":1}`, wantErr: errJSONNotString},
		{name: "value is an object", doc: `{"a":{}}`, wantErr: errJSONNotString},
		{name: "value carries an escape", doc: `{"a":"x\ny"}`, wantErr: errJSONEscapedValue},
		{name: "member twice", doc: `{"a":"x","a":"x"}`, wantErr: errJSONDuplicateMember},
		{name: "escaped member name", doc: `{"\u0061":"x"}`, wantErr: errJSONEscapedKey},
		{name: "escaped name on another member", doc: `{"\u0062":1,"a":"x"}`, wantErr: errJSONEscapedKey},
		{name: "escaped duplicate of the target", doc: `{"a":"x","\u0061":"y"}`, wantErr: errJSONEscapedKey},
		{name: "not an object", doc: `[1]`, wantErr: errJSONMalformed},
		{name: "empty document", doc: ``, wantErr: errJSONMalformed},
		{name: "unterminated object", doc: `{"b":1`, wantErr: errJSONMalformed},
		{name: "unterminated string", doc: `{"a":"x`, wantErr: errJSONMalformed},
		{name: "missing colon", doc: `{"a" "x"}`, wantErr: errJSONMalformed},
		{name: "missing separator", doc: `{"b":1 "c":2}`, wantErr: errJSONMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jsonStringMember([]byte(tt.doc), "a")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("value = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestJSONStringMember_ReturnsSubSlice verifies the scan hands back a window
// onto the document rather than a copy of it. A copy would be exactly the heap
// allocation this whole path exists to avoid.
func TestJSONStringMember_ReturnsSubSlice(t *testing.T) {
	document := []byte(`{"a":"xyz"}`)

	value, err := jsonStringMember(document, "a")
	if err != nil {
		t.Fatalf("jsonStringMember failed: %v", err)
	}

	// Mutating the document through the returned slice proves they share
	// backing memory.
	value[0] = 'Q'
	if !strings.Contains(string(document), `"Qyz"`) {
		t.Errorf("returned value is a copy of the document, not a window onto it: %s", document)
	}
}

// legacyKeyPackageDocument builds a key-package document the way encoding/json
// built it when StoredKeyPackage still carried the share as a plaintext
// SecretShare field. It is the fixture for reading a store written before the
// share moved into protected memory - the case Seal must stay compatible with.
//
// A test may hold the plaintext share on the heap; production code may not,
// which is why this construction lives here and not in the package.
func legacyKeyPackageDocument(t *testing.T, kp *frost.KeyPackage, keyID, groupID string) []byte {
	t.Helper()

	verificationShares := make([]StoredVerificationShare, len(kp.VerificationShares))
	for i, vs := range kp.VerificationShares {
		verificationShares[i] = StoredVerificationShare{
			Identifier:      vs.Identifier,
			VerificationKey: vs.VerificationKey.Bytes(),
		}
	}

	document, err := json.Marshal(&struct {
		SecretShare        []byte
		Identifier         frost.Identifier
		GroupPublicKey     []byte
		VerificationShares []StoredVerificationShare
		Metadata           KeyMetadata
	}{
		SecretShare:        kp.SecretShare.Bytes(),
		Identifier:         kp.Identifier,
		GroupPublicKey:     kp.GroupPublicKey.Bytes(),
		VerificationShares: verificationShares,
		Metadata: KeyMetadata{
			KeyID:      keyID,
			GroupID:    groupID,
			MinSigners: 2,
			MaxSigners: 3,
			CreatedAt:  1000,
			UpdatedAt:  1000,
			Tags:       map[string]string{},
		},
	})
	if err != nil {
		t.Fatalf("failed to build the legacy document: %v", err)
	}

	return document
}

// TestOpenStoredKeyPackage_RejectsEscapedMemberName closes a parser
// differential between this package's share scan and encoding/json.
//
// encoding/json unescapes member names; the scan compares raw bytes. So
// "\u0053ecretShare" is a second SecretShare to the decoder and an unrelated
// member to the scan. A document carrying both would look to the scan as
// though it carried the share exactly once - passing the duplicate check -
// while the two parsers disagreed about which share it holds. Measured before
// the fix, on the document below: encoding/json resolved the share to bbbbbbbb
// and the scan to aaaaaaaa, and the document was accepted.
//
// Nothing this package writes carries an escaped name, so rejecting every one
// of them closes the difference without an unescaping pass through the heap.
func TestOpenStoredKeyPackage_RejectsEscapedMemberName(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte{0xAA, 0xAA, 0xAA, 0xAA})
	second := base64.StdEncoding.EncodeToString([]byte{0xBB, 0xBB, 0xBB, 0xBB})

	doc := `{"Identifier":7,"SecretShare":"` + first + `","\u0053ecretShare":"` + second + `"}`

	// encoding/json really does read this as two SecretShare members and take
	// the second, which is what makes the disagreement worth rejecting.
	var probe struct {
		SecretShare []byte
	}
	if err := json.Unmarshal([]byte(doc), &probe); err != nil {
		t.Fatalf("encoding/json rejected the fixture, so it no longer demonstrates the case: %v", err)
	}
	if !bytes.Equal(probe.SecretShare, []byte{0xBB, 0xBB, 0xBB, 0xBB}) {
		t.Fatalf("encoding/json resolved the share to %x, want bbbbbbbb; the fixture no longer "+
			"demonstrates the differential", probe.SecretShare)
	}

	payload := secmem.NewSecretBytes([]byte(doc))
	defer payload.Destroy()

	storedKP, err := OpenStoredKeyPackage(payload)
	if !errors.Is(err, errJSONEscapedKey) {
		t.Errorf("error = %v, want the escaped-name rejection", err)
	}
	if storedKP != nil {
		t.Error("a document with an escaped member name still produced a key package")
	}
}
