package main

import (
	"regexp"
	"testing"
)

func TestRandRunes(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "generate string with length 0",
			length: 0,
		},
		{
			name:   "generate string with length 1",
			length: 1,
		},
		{
			name:   "generate string with length 10",
			length: 10,
		},
		{
			name:   "generate string with length 32",
			length: 32,
		},
		{
			name:   "generate string with length 100",
			length: 100,
		},
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	charsetRegex := regexp.MustCompile("^[" + regexp.QuoteMeta(charset) + "]*$")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := randRunes(tt.length)

			// Check correct length
			if len(result) != tt.length {
				t.Errorf("randRunes() returned string of length %d, want %d", len(result), tt.length)
			}

			// Check all characters are from the charset
			if !charsetRegex.MatchString(result) {
				t.Errorf("randRunes() returned string with invalid characters: %s", result)
			}
		})
	}
}

func TestRandRunesUniqueness(t *testing.T) {
	// Generate multiple strings and ensure they are different (with high probability)
	length := 32
	iterations := 1_000_000
	results := make(map[string]bool)

	for i := 0; i < iterations; i++ {
		result := randRunes(length)
		if results[result] {
			t.Errorf("randRunes() generated duplicate string: %s", result)
		}
		results[result] = true
	}

	// With 32 characters from a large charset, duplicates should be extremely unlikely
	if len(results) != iterations {
		t.Errorf("randRunes() generated %d unique strings out of %d, expected all unique", len(results), iterations)
	}
}
