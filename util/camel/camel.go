package camel

import (
	"strings"
	"unicode"
)

// SnakeUpper converts a camelCase string to an uppercase SNAKE_CASE string.
// For example: "myVariable" -> "MY_VARIABLE", "APIService" -> "API_SERVICE".
func SnakeUpper(s string) string { return snake(s, unicode.ToUpper) }

// SnakeLower converts a camelCase string to a lowercase snake_case string.
// For example: "myVariable" -> "my_variable", "APIService" -> "api_service".
func SnakeLower(s string) string { return snake(s, unicode.ToLower) }

func snake(s string, toCase func(rune) rune) string {
	var b strings.Builder
	b.Grow(len(s) + 5)
	runes := []rune(s)
	for i, r := range runes {
		// Insert an underscore before a capital letter or digit.
		if i != 0 {
			q := runes[i-1]
			if (unicode.IsLower(q) &&
				// Case 1: Lowercase to uppercase/digit transition ("myVar", "myVar1").
				(unicode.IsUpper(r) || unicode.IsDigit(r))) ||
				(unicode.IsUpper(q) &&
					// Case 2: Acronym to new word transition ("MYVar").
					unicode.IsUpper(r) &&
					i+1 < len(runes) &&
					unicode.IsLower(runes[i+1])) {
				b.WriteRune('_')
			}
		}
		b.WriteRune(toCase(r))
	}
	return b.String()
}
