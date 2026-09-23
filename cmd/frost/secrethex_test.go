package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestSecretHex_MarshalsAsHexString(t *testing.T) {
	s := newSecretHex([]byte{0xde, 0xad, 0xbe, 0xef})

	got, err := json.Marshal(struct {
		Secret secretHex `json:"secret"`
	}{s})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `{"secret":"deadbeef"}`; string(got) != want {
		t.Errorf("Marshal = %s, want %s", got, want)
	}
}

func TestSecretHex_ZeroValueMarshalsAsEmptyString(t *testing.T) {
	var s secretHex

	got, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != `""` {
		t.Errorf("Marshal = %s, want \"\"", got)
	}
}

func TestSecretHex_RoundTrip(t *testing.T) {
	raw := []byte{0x00, 0x01, 0xfe, 0xff}
	data, err := json.Marshal(newSecretHex(raw))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var s secretHex
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	got, err := s.decode()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("decode = %x, want %x", got, raw)
	}
}

// TestSecretHex_UnmarshalDoesNotAliasInput is the property the type exists
// for: the caller scrubs the file buffer after json.Unmarshal, so the secret
// must have been copied into memory the secretHex owns.
func TestSecretHex_UnmarshalDoesNotAliasInput(t *testing.T) {
	input := []byte(`{"secret":"0a0b"}`)
	var v struct {
		Secret secretHex `json:"secret"`
	}
	if err := json.Unmarshal(input, &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for i := range input {
		input[i] = 0
	}

	got, err := v.Secret.decode()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, []byte{0x0a, 0x0b}) {
		t.Errorf("decode after scrubbing input = %x, want 0a0b", got)
	}
}

func TestSecretHex_ZeroScrubsOwnedBytes(t *testing.T) {
	var s secretHex
	if err := json.Unmarshal([]byte(`"a1b2c3"`), &s); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	backing := []byte(s)

	s.zero()

	for i, b := range backing {
		if b != 0 {
			t.Fatalf("byte %d = %#x after zero, want 0", i, b)
		}
	}
}

// TestSecretHex_ZeroIsSafeOnLiteralBackedValue pins the defect behind
// go-frost#15: a helper that wrote through a string literal's read-only
// backing array killed the process. secretHex only ever writes to bytes it
// allocated, so a value built from a literal scrubs without faulting.
func TestSecretHex_ZeroIsSafeOnLiteralBackedValue(t *testing.T) {
	s := newSecretHex([]byte("a literal secret"))
	s.zero()

	var empty secretHex
	empty.zero()
}

func TestSecretHex_NullLeavesValueUnset(t *testing.T) {
	var v struct {
		Secret secretHex `json:"secret"`
	}
	if err := json.Unmarshal([]byte(`{"secret":null}`), &v); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if v.Secret != nil {
		t.Errorf("Secret = %q, want nil", []byte(v.Secret))
	}
}

func TestSecretHex_RejectsNonString(t *testing.T) {
	for _, input := range []string{`12`, `true`, `{}`, `[]`} {
		t.Run(input, func(t *testing.T) {
			var s secretHex
			err := json.Unmarshal([]byte(input), &s)
			if !errors.Is(err, errSecretHexNotString) {
				t.Errorf("Unmarshal(%s) error = %v, want errSecretHexNotString", input, err)
			}
		})
	}
}

// TestSecretHex_AcceptsEscapedHexDigits keeps files that spell hex digits
// with JSON escapes readable, as they were when the field was a Go string.
func TestSecretHex_AcceptsEscapedHexDigits(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []byte
	}{
		{"one escaped digit", "\"0\\u0030ff\"", []byte{0x00, 0xff}},
		{"all escaped", "\"\\u0041\\u0062\"", []byte{0xab}},
		{"upper-case escape hex", "\"\\u004A\\u0066\"", nil},
		{"escaped solidus is not a hex digit", "\"\\/0\"", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []byte(`{"secret":` + tt.input + `}`)
			var v struct {
				Secret secretHex `json:"secret"`
			}
			if err := json.Unmarshal(input, &v); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			for i := range input {
				input[i] = 0
			}

			got, err := v.Secret.decode()
			if tt.want == nil {
				if err == nil {
					t.Fatalf("decode = %x, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("decode = %x, want %x", got, tt.want)
			}
		})
	}
}

// TestSecretHex_EscapedInputMatchesPlainString pins compatibility with the
// previous string field: encoding/json's own unescaping and secretHex's must
// yield the same hex text for every escape form JSON allows.
func TestSecretHex_EscapedInputMatchesPlainString(t *testing.T) {
	inputs := []string{
		"\"\\u0030\\u0031\"",
		"\"a\\u0062c\\u0044\"",
		"\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"",
		"\"\\u00e9\\u20ac\"",
		"\"\\ud83d\\ude00\"",
		"\"\\ud83d0\"",
		"\"\\ude00\"",
		"\"\\ud83d\\u0041\"",
		"\"caf\u00e9\"",
		"\"\xff0\\u0031\"",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			var plain string
			if err := json.Unmarshal([]byte(input), &plain); err != nil {
				t.Fatalf("Unmarshal into string: %v", err)
			}
			var s secretHex
			if err := json.Unmarshal([]byte(input), &s); err != nil {
				t.Fatalf("Unmarshal into secretHex: %v", err)
			}
			if got := string(s[1 : len(s)-1]); got != plain {
				t.Errorf("secretHex holds %q, encoding/json gives %q", got, plain)
			}
		})
	}
}

func TestSecretHex_DecodeRejectsInvalidHex(t *testing.T) {
	for _, input := range []string{`"zz"`, `"abc"`} {
		t.Run(input, func(t *testing.T) {
			var s secretHex
			if err := json.Unmarshal([]byte(input), &s); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if _, err := s.decode(); err == nil {
				t.Errorf("decode(%s) succeeded, want an error", input)
			}
		})
	}
}

// TestAppendUnquoted_RejectsMalformedEscapes covers the guard encoding/json
// never lets through: its scanner rejects these before UnmarshalJSON runs.
func TestAppendUnquoted_RejectsMalformedEscapes(t *testing.T) {
	for _, body := range []string{"\\", "\\x", "\\u12", "\\u12g4"} {
		t.Run(body, func(t *testing.T) {
			if got, ok := appendUnquoted(nil, []byte(body)); ok {
				t.Errorf("appendUnquoted(%q) = %q, ok; want failure", body, got)
			}
		})
	}
}

func TestSecretHex_UnmarshalJSONRejectsMalformedEscapeDirectly(t *testing.T) {
	s := newSecretHex([]byte{0x01})
	err := s.UnmarshalJSON([]byte("\"0\\x\""))
	if !errors.Is(err, errSecretHexNotString) {
		t.Fatalf("UnmarshalJSON error = %v, want errSecretHexNotString", err)
	}
	if got, derr := s.decode(); derr != nil || !bytes.Equal(got, []byte{0x01}) {
		t.Errorf("value after failed UnmarshalJSON = %x, %v; want it unchanged", got, derr)
	}
}
