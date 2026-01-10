package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "Valid API Key",
			headers:       http.Header{"Authorization": []string{"ApiKey myvalidkey123"}},
			expectedKey:   "myvalidkey123",
			expectedError: nil,
		},
		{
			name:          "Missing Authorization Header",
			headers:       http.Header{}, // Empty headers map
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded, // Expect the specific custom error
		},
		{
			name:          "Malformed Header - Wrong Prefix",
			headers:       http.Header{"Authorization": []string{"Bearer someothertoken"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"), // Expect the generic "malformed" error
		},
		{
			name:          "Malformed Header - Missing Key Value",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"), // Expect the generic "malformed" error
		},
		{
			name:          "Malformed Header - Empty Value",
			headers:       http.Header{"Authorization": []string{"ApiKey "}},
			expectedKey:   "",  // Note: strings.Split treats the space after "ApiKey" as the second element if you split on just " "
			expectedError: nil, // The current function returns " " as the key, which is technically a success path based on your logic
		},
	}

	// Iterate over the test cases and run them as subtests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotError := GetAPIKey(tt.headers)

			// 1. Check the returned key
			if gotKey != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, gotKey)
			}

			// 2. Check the returned error
			// Use errors.Is to check for specific error types (if applicable)
			if !errors.Is(gotError, tt.expectedError) {
				// Special handling for the generic "malformed authorization header" error
				// because it is created inline using errors.New()
				if tt.expectedError != nil && gotError != nil && gotError.Error() == tt.expectedError.Error() {
					return // Errors match by message
				}
				if tt.expectedError == nil && gotError == nil {
					return // Both are nil, which is correct
				}
				t.Errorf("expected error %v, got %v", tt.expectedError, gotError)
			}
		})
	}
}
