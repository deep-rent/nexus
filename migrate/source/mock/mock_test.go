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

package mock_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/source/mock"
)

func TestNew(t *testing.T) {
	t.Parallel()

	scripts := []migrate.SourceScript{
		{Version: 1, Description: "init"},
	}
	s := mock.New(scripts...)

	if s == nil {
		t.Fatal("mock.New() = nil; want non-nil")
	}

	if !reflect.DeepEqual(s.Scripts, scripts) {
		t.Errorf("New(%v).Scripts = %v; want %v", scripts, s.Scripts, scripts)
	}
}

func TestSource_List(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		want := []migrate.SourceScript{
			{Version: 1, Description: "1st", Content: []byte("SELECT 1;")},
			{Version: 2, Description: "2nd", Content: []byte("SELECT 2;")},
		}
		s := mock.New(want...)

		got, err := s.List()
		if err != nil {
			t.Fatalf("List() err = %v; want nil", err)
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("List() = %v; want %v", got, want)
		}

		// Verify deep copy by mutating result
		got[0].Version = 999
		if s.Scripts[0].Version == got[0].Version {
			t.Errorf("List() returned reference; want deep copy")
		}
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()

		wantErr := errors.New("list failed")
		s := mock.New()
		s.ListErr = wantErr

		got, err := s.List()
		if !errors.Is(err, wantErr) {
			t.Errorf("List() err = %v; want %v", err, wantErr)
		}

		if got != nil {
			t.Errorf("List() = %v; want nil", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		s := mock.New()
		got, err := s.List()
		if err != nil {
			t.Fatalf("List() err = %v; want nil", err)
		}

		if len(got) != 0 {
			t.Errorf("len(List()) = %d; want 0", len(got))
		}
	})
}
