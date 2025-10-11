package snake_test

import (
	"testing"

	"github.com/deep-rent/nexus/util/snake"
	"github.com/stretchr/testify/assert"
)

func TestToUpper(t *testing.T) {
	type test struct {
		name string
		in   string
		want string
	}

	tests := []test{
		{"simple", "myVariable", "MY_VARIABLE"},
		{"acronym start", "APIService", "API_SERVICE"},
		{"acronym middle", "myAPIService", "MY_API_SERVICE"},
		{"acronym end", "serviceAPI", "SERVICE_API"},
		// {"with digits", "version123Update", "VERSION_123_UPDATE"},
		{"all caps", "ID", "ID"},
		{"single word", "test", "TEST"},
		{"empty string", "", ""},
		{"already snake", "MY_VARIABLE", "MY_VARIABLE"},
		{"leading lowercase", "aBC", "A_BC"},
		// {"number transition", "var1ToVar2", "VAR_1_TO_VAR_2"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := snake.ToUpper(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestToLower(t *testing.T) {
	type test struct {
		name string
		in   string
		want string
	}

	tests := []test{
		{"simple", "myVariable", "my_variable"},
		{"acronym start", "APIService", "api_service"},
		{"acronym middle", "myAPIService", "my_api_service"},
		{"acronym end", "serviceAPI", "service_api"},
		// {"with digits", "version123Update", "version_123_update"},
		{"all caps", "ID", "id"},
		{"single word", "test", "test"},
		{"empty string", "", ""},
		{"already snake", "my_variable", "my_variable"},
		{"leading lowercase", "aBC", "a_bc"},
		// {"number transition", "var1ToVar2", "var_1_to_var_2"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := snake.ToLower(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}
