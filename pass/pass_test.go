// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pass_test

import (
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"testing"

	"github.com/deep-rent/nexus/pass"
)

// testIterations keeps the derivation cheap in tests; production defaults
// are exercised via [pass.Algorithm.Outdated] instead of full derivations.
const testIterations = 1000

// newHasher builds a [pass.Hasher] whose default and fallback algorithms
// use the reduced test iteration count.
func newHasher(opts ...pass.Option) *pass.Hasher {
	return pass.New(append([]pass.Option{
		pass.WithAlgorithm(pass.PBKDF2SHA512(testIterations)),
		pass.WithDefault(pass.PBKDF2SHA256(testIterations)),
	}, opts...)...)
}

// fakeAlgorithm is a trivial (insecure) [pass.Algorithm] for testing
// dynamic dispatch and migration scenarios.
type fakeAlgorithm struct {
	name string
}

func (f *fakeAlgorithm) Name() string { return f.name }

func (f *fakeAlgorithm) Hash(password string) (pass.Record, error) {
	return pass.Record{
		Algorithm: f.name,
		Digest:    []byte(f.name + ":" + password),
	}, nil
}

func (f *fakeAlgorithm) Verify(
	rec pass.Record,
	password string,
) (bool, error) {
	return string(rec.Digest) == f.name+":"+password, nil
}

func (f *fakeAlgorithm) Outdated(pass.Record) bool { return false }

var _ pass.Algorithm = (*fakeAlgorithm)(nil)

func TestHashVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		alg  pass.Algorithm
	}{
		{name: "pbkdf2-sha256", alg: pass.PBKDF2SHA256(testIterations)},
		{name: "pbkdf2-sha512", alg: pass.PBKDF2SHA512(testIterations)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := pass.New(pass.WithDefault(tt.alg))

			record, err := h.Hash("correct horse battery staple")
			if err != nil {
				t.Fatalf("Hash returned error: %v", err)
			}

			ok, err := h.Verify(record, "correct horse battery staple")
			if err != nil {
				t.Fatalf("Verify returned error: %v", err)
			}
			if !ok {
				t.Error("correct password should verify")
			}

			ok, err = h.Verify(record, "correct horse battery stable")
			if err != nil {
				t.Fatalf("Verify returned error: %v", err)
			}
			if ok {
				t.Error("wrong password should not verify")
			}
		})
	}
}

func TestHash_RecordShape(t *testing.T) {
	t.Parallel()

	h := newHasher()

	record, err := h.Hash("s3cret")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	var rec pass.Record
	if err := json.Unmarshal(record, &rec); err != nil {
		t.Fatalf("failed to decode record %q: %v", record, err)
	}

	if rec.Algorithm != pass.AlgorithmPBKDF2SHA256 {
		t.Errorf(
			"got algorithm %q; want %q",
			rec.Algorithm,
			pass.AlgorithmPBKDF2SHA256,
		)
	}
	if rec.Iterations != testIterations {
		t.Errorf("got %d iterations; want %d", rec.Iterations, testIterations)
	}
	if len(rec.Salt) != 16 {
		t.Errorf("got %d salt bytes; want 16", len(rec.Salt))
	}
	if len(rec.Digest) != 32 {
		t.Errorf("got %d digest bytes; want 32", len(rec.Digest))
	}
}

func TestHash_UniqueSalts(t *testing.T) {
	t.Parallel()

	h := newHasher()

	a, err := h.Hash("s3cret")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	b, err := h.Hash("s3cret")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	if string(a) == string(b) {
		t.Error("equal passwords must hash to different records")
	}
}

// TestVerify_KnownVectors pins the PBKDF2-HMAC-SHA256 derivation to
// published test vectors, guarding against silent changes in the
// underlying primitive or record wiring.
func TestVerify_KnownVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		iterations int
		digest     string // hex
	}{
		{
			name:       "1 iteration",
			iterations: 1,
			digest: "120fb6cffcf8b32c43e7225256c4f83" +
				"7a86548c92ccc35480805987cb70be17b",
		},
		{
			name:       "4096 iterations",
			iterations: 4096,
			digest: "c5e478d59288c841aa530db6845c4c8" +
				"d962893a001ce4e11a4963873aa98134a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			digest, err := hex.DecodeString(tt.digest)
			if err != nil {
				t.Fatalf("invalid vector digest: %v", err)
			}

			record, err := json.Marshal(pass.Record{
				Algorithm:  pass.AlgorithmPBKDF2SHA256,
				Iterations: tt.iterations,
				Salt:       []byte("salt"),
				Digest:     digest,
			})
			if err != nil {
				t.Fatalf("failed to encode record: %v", err)
			}

			h := newHasher()
			ok, err := h.Verify(record, "password")
			if err != nil {
				t.Fatalf("Verify returned error: %v", err)
			}
			if !ok {
				t.Error("known vector should verify")
			}
		})
	}
}

func TestVerify_TamperedDigest(t *testing.T) {
	t.Parallel()

	h := newHasher()

	record, err := h.Hash("s3cret")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}

	var rec pass.Record
	if err := json.Unmarshal(record, &rec); err != nil {
		t.Fatalf("failed to decode record: %v", err)
	}
	rec.Digest[0] ^= 0xff
	tampered, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("failed to encode record: %v", err)
	}

	ok, err := h.Verify(tampered, "s3cret")
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if ok {
		t.Error("tampered digest should not verify")
	}
}

func TestVerify_UnknownAlgorithm(t *testing.T) {
	t.Parallel()

	h := newHasher()

	record := []byte(`{"alg":"argon2id","digest":"aGVsbG8gd29ybGQhIQ=="}`)
	if _, err := h.Verify(
		record,
		"s3cret",
	); !errors.Is(err, pass.ErrUnknownAlgorithm) {
		t.Errorf("got %v; want ErrUnknownAlgorithm", err)
	}
}

func TestVerify_MalformedRecords(t *testing.T) {
	t.Parallel()

	// A valid digest value for splicing into malformed records.
	digest := `"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="`

	tests := []struct {
		name   string
		record string
	}{
		{
			name:   "invalid JSON",
			record: `not json`,
		},
		{
			name:   "missing algorithm",
			record: `{"iter":1000,"salt":"c2FsdA==","digest":` + digest + `}`,
		},
		{
			name: "zero iterations",
			record: `{"alg":"pbkdf2-sha256",` +
				`"salt":"c2FsdA==","digest":` + digest + `}`,
		},
		{
			name: "negative iterations",
			record: `{"alg":"pbkdf2-sha256","iter":-1,` +
				`"salt":"c2FsdA==","digest":` + digest + `}`,
		},
		{
			name: "missing salt",
			record: `{"alg":"pbkdf2-sha256","iter":1000,` +
				`"digest":` + digest + `}`,
		},
		{
			name: "digest too short",
			record: `{"alg":"pbkdf2-sha256","iter":1000,` +
				`"salt":"c2FsdA==","digest":"c2hvcnQ="}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHasher()
			if _, err := h.Verify(
				[]byte(tt.record),
				"s3cret",
			); !errors.Is(err, pass.ErrMalformedRecord) {
				t.Errorf("got %v; want ErrMalformedRecord", err)
			}
		})
	}
}

func TestOutdated(t *testing.T) {
	t.Parallel()

	t.Run("current record is not outdated", func(t *testing.T) {
		t.Parallel()
		h := newHasher()

		record, err := h.Hash("s3cret")
		if err != nil {
			t.Fatalf("Hash returned error: %v", err)
		}

		outdated, err := h.Outdated(record)
		if err != nil {
			t.Fatalf("Outdated returned error: %v", err)
		}
		if outdated {
			t.Error("fresh record should not be outdated")
		}
	})

	t.Run("fewer iterations are outdated", func(t *testing.T) {
		t.Parallel()

		record, err := newHasher().Hash("s3cret")
		if err != nil {
			t.Fatalf("Hash returned error: %v", err)
		}

		// The same algorithm, now configured with a higher work factor.
		h := pass.New(
			pass.WithDefault(pass.PBKDF2SHA256(testIterations + 1)),
		)

		outdated, err := h.Outdated(record)
		if err != nil {
			t.Fatalf("Outdated returned error: %v", err)
		}
		if !outdated {
			t.Error("record with fewer iterations should be outdated")
		}
	})

	t.Run("different algorithm is outdated", func(t *testing.T) {
		t.Parallel()

		record, err := pass.New(
			pass.WithDefault(pass.PBKDF2SHA512(testIterations)),
		).Hash("s3cret")
		if err != nil {
			t.Fatalf("Hash returned error: %v", err)
		}

		outdated, err := newHasher().Outdated(record)
		if err != nil {
			t.Fatalf("Outdated returned error: %v", err)
		}
		if !outdated {
			t.Error("record of a non-default algorithm should be outdated")
		}
	})

	t.Run("malformed record errors", func(t *testing.T) {
		t.Parallel()
		h := newHasher()

		if _, err := h.Outdated(
			[]byte(`not json`),
		); !errors.Is(err, pass.ErrMalformedRecord) {
			t.Errorf("got %v; want ErrMalformedRecord", err)
		}
	})
}

func TestOutdated_Defaults(t *testing.T) {
	t.Parallel()

	// Checked without running full derivations: a record carrying the
	// documented default parameters must satisfy the default
	// configuration.
	tests := []struct {
		name       string
		alg        pass.Algorithm
		algName    string
		iterations int
		keyLength  int
	}{
		{
			name:       "pbkdf2-sha256",
			alg:        pass.PBKDF2SHA256(0),
			algName:    pass.AlgorithmPBKDF2SHA256,
			iterations: pass.DefaultSHA256Iterations,
			keyLength:  32,
		},
		{
			name:       "pbkdf2-sha512",
			alg:        pass.PBKDF2SHA512(0),
			algName:    pass.AlgorithmPBKDF2SHA512,
			iterations: pass.DefaultSHA512Iterations,
			keyLength:  64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			current := pass.Record{
				Algorithm:  tt.algName,
				Iterations: tt.iterations,
				Digest:     make([]byte, tt.keyLength),
			}
			if tt.alg.Outdated(current) {
				t.Error("record with default parameters should not be outdated")
			}

			weaker := current
			weaker.Iterations--
			if !tt.alg.Outdated(weaker) {
				t.Error("record below default iterations should be outdated")
			}

			truncated := current
			truncated.Digest = make([]byte, tt.keyLength-1)
			if !tt.alg.Outdated(truncated) {
				t.Error("record with truncated digest should be outdated")
			}
		})
	}
}

func TestCustomAlgorithm(t *testing.T) {
	t.Parallel()

	legacy := &fakeAlgorithm{name: "legacy"}

	t.Run("verifies records of registered algorithms", func(t *testing.T) {
		t.Parallel()

		// New hashes use the default; legacy records still verify.
		h := newHasher(pass.WithAlgorithm(legacy))

		rec, err := legacy.Hash("s3cret")
		if err != nil {
			t.Fatalf("Hash returned error: %v", err)
		}
		record, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("failed to encode record: %v", err)
		}

		ok, err := h.Verify(record, "s3cret")
		if err != nil {
			t.Fatalf("Verify returned error: %v", err)
		}
		if !ok {
			t.Error("legacy record should verify")
		}

		// Legacy records must be flagged for rehashing.
		outdated, err := h.Outdated(record)
		if err != nil {
			t.Fatalf("Outdated returned error: %v", err)
		}
		if !outdated {
			t.Error("legacy record should be outdated")
		}
	})

	t.Run("hashes with a custom default", func(t *testing.T) {
		t.Parallel()

		h := pass.New(pass.WithDefault(legacy))

		record, err := h.Hash("s3cret")
		if err != nil {
			t.Fatalf("Hash returned error: %v", err)
		}

		var rec pass.Record
		if err := json.Unmarshal(record, &rec); err != nil {
			t.Fatalf("failed to decode record: %v", err)
		}
		if rec.Algorithm != "legacy" {
			t.Errorf("got algorithm %q; want %q", rec.Algorithm, "legacy")
		}

		// The built-in algorithms remain registered as a fallback.
		builtin, err := newHasher().Hash("s3cret")
		if err != nil {
			t.Fatalf("Hash returned error: %v", err)
		}
		if ok, err := h.Verify(builtin, "s3cret"); err != nil || !ok {
			t.Errorf("built-in record should verify; got %v, %v", ok, err)
		}
	})
}

func TestPanics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		fn   func()
	}{
		{
			name: "nil default algorithm",
			fn:   func() { pass.New(pass.WithDefault(nil)) },
		},
		{
			name: "nil registered algorithm",
			fn:   func() { pass.New(pass.WithAlgorithm(nil)) },
		},
		{
			name: "unnamed algorithm",
			fn: func() {
				pass.New(pass.WithAlgorithm(&fakeAlgorithm{name: ""}))
			},
		},
		{
			name: "negative iterations",
			fn:   func() { pass.PBKDF2SHA256(-1) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if recover() == nil {
					t.Error("expected panic")
				}
			}()
			tt.fn()
		})
	}
}
