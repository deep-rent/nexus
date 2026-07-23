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

package oauth

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/deep-rent/nexus/sec/nonce"
)

// exhaustedSource simulates an exhausted entropy source.
type exhaustedSource struct{}

func (exhaustedSource) Read(context.Context, []byte) error {
	return errors.New("entropy source exhausted")
}

func TestNewUserCode(t *testing.T) {
	t.Parallel()

	t.Run("format", func(t *testing.T) {
		t.Parallel()
		s := &Server{userCodes: nonce.NewSampler(
			nil,
			UserCodeAlphabet,
			UserCodeLength,
		)}
		pattern := regexp.MustCompile(
			`^[` + UserCodeAlphabet + `]{4}-[` + UserCodeAlphabet + `]{4}$`,
		)
		for range 100 {
			code, err := s.newUserCode(t.Context())
			if err != nil {
				t.Fatalf("should not have returned an error: %v", err)
			}
			if !pattern.MatchString(code) {
				t.Fatalf("user code %q does not match %q", code, pattern)
			}
		}
	})

	t.Run("propagates source failure", func(t *testing.T) {
		t.Parallel()
		s := &Server{userCodes: nonce.NewSampler(
			exhaustedSource{},
			UserCodeAlphabet,
			UserCodeLength,
		)}
		if _, err := s.newUserCode(t.Context()); err == nil {
			t.Error("expected an error from the failing source")
		}
	})
}

func TestNormalizeUserCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"BCDF-GHJK", "BCDF-GHJK"},
		{"bcdf-ghjk", "BCDF-GHJK"},
		{"bcdfghjk", "BCDF-GHJK"},
		{" bcdf ghjk ", "BCDF-GHJK"},
		{"bcd", "BCD"},
	}

	for _, tt := range tests {
		if got := normalizeUserCode(tt.in); got != tt.want {
			t.Errorf("normalizeUserCode(%q) = %q; want %q", tt.in, got, tt.want)
		}
	}
}
