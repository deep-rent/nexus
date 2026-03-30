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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/deep-rent/nexus/migrate"
	"github.com/deep-rent/nexus/migrate/source/mock"
)

func TestNewSource(t *testing.T) {
	scripts := []migrate.SourceScript{
		{Version: 1, Description: "init"},
	}
	s := mock.New(scripts...)

	require.NotNil(t, s)
	assert.Equal(t, scripts, s.Scripts)
}

func TestSource_List(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expected := []migrate.SourceScript{
			{Version: 1, Description: "1st", Content: []byte("SELECT 1;")},
			{Version: 2, Description: "2nd", Content: []byte("SELECT 2;")},
		}
		s := mock.New(expected...)

		actual, err := s.List()
		require.NoError(t, err)
		assert.Equal(t, expected, actual)

		actual[0].Version = 999
		assert.NotEqual(t, s.Scripts[0].Version, actual[0].Version)
	})

	t.Run("error", func(t *testing.T) {
		wantErr := errors.New("list failed")
		s := mock.New()
		s.ListErr = wantErr

		scripts, err := s.List()
		assert.ErrorIs(t, err, wantErr)
		assert.Nil(t, scripts)
	})

	t.Run("empty", func(t *testing.T) {
		s := mock.New()
		scripts, err := s.List()
		assert.NoError(t, err)
		assert.Empty(t, scripts)
	})
}
