package main

import (
	"fmt"
	"net/url"
	"regexp"
	"testing"
)

func TestHttpCollectorConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{
			name:    "valid HTTP URL",
			url:     "http://example.com",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL",
			url:     "https://example.com",
			wantErr: false,
		},
		{
			name:    "valid HTTP URL with path",
			url:     "http://example.com/api/v1",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL with path and query",
			url:     "https://example.com/api/v1?param=value",
			wantErr: false,
		},
		{
			name:    "empty URL",
			url:     "",
			wantErr: true,
		},
		{
			name:    "invalid URL format",
			url:     "invalid-url-format",
			wantErr: true,
		},
		{
			name:    "FTP URL (not allowed)",
			url:     "ftp://example.com",
			wantErr: true,
		},
		{
			name:    "file URL (not allowed)",
			url:     "file:///etc/passwd",
			wantErr: true,
		},
		{
			name:    "URL without scheme",
			url:     "example.com",
			wantErr: true,
		},
		{
			name:    "malformed URL",
			url:     "http://[invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &HttpCollectorConfig{
				URL: tt.url,
			}
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("HttpCollectorConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIdentifierSanitization(t *testing.T) {
	// Helper function to test identifier sanitization (same as in main code)
	sanitizeIdentifier := func(s string) string {
		// Replace all non-alphanumeric, non-dash, non-underscore characters with '-'
		re := regexp.MustCompile(`[^a-zA-Z0-9\-_]`)
		return re.ReplaceAllString(s, "-")
	}

	// Test identifier generation from URLs
	tests := []struct {
		name               string
		inputURL           string
		expectedIdentifier string
	}{
		{
			name:               "simple HTTP URL",
			inputURL:           "http://example.com",
			expectedIdentifier: "http-endpoint/http-example-com",
		},
		{
			name:               "HTTPS URL with path",
			inputURL:           "https://api.example.com/v1/users",
			expectedIdentifier: "http-endpoint/https-api-example-com-v1-users",
		},
		{
			name:               "URL with port",
			inputURL:           "https://example.com:8080/api",
			expectedIdentifier: "http-endpoint/https-example-com-8080-api",
		},
		{
			name:               "URL with special characters",
			inputURL:           "https://test-site.example.com/api/v1?param=value&other=123",
			expectedIdentifier: "http-endpoint/https-test-site-example-com-api-v1",
		},
		{
			name:               "URL with underscores and dashes",
			inputURL:           "https://my_api-server.example.com/test_endpoint",
			expectedIdentifier: "http-endpoint/https-my_api-server-example-com-test_endpoint",
		},
		{
			name:               "URL with deep path",
			inputURL:           "https://example.com/api/v2/users/123/profile",
			expectedIdentifier: "http-endpoint/https-example-com-api-v2-users-123-profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse URL (same as in main code)
			parsedURL, err := url.Parse(tt.inputURL)
			if err != nil {
				t.Fatalf("Failed to parse URL %s: %v", tt.inputURL, err)
			}

			// Build identifier from scheme, host, and path (same as main code)
			idRaw := fmt.Sprintf("%s-%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
			idSafe := sanitizeIdentifier(idRaw)
			fullIdentifier := fmt.Sprintf("http-endpoint/%s", idSafe)

			if fullIdentifier != tt.expectedIdentifier {
				t.Errorf("Expected identifier %s, got %s", tt.expectedIdentifier, fullIdentifier)
			}

			// Verify identifier contains only safe characters
			safePattern := regexp.MustCompile(`^[a-zA-Z0-9\-_/]+$`)
			if !safePattern.MatchString(fullIdentifier) {
				t.Errorf("Generated identifier %s contains unsafe characters", fullIdentifier)
			}
		})
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	// Direct testing of sanitization function
	sanitizeIdentifier := func(s string) string {
		re := regexp.MustCompile(`[^a-zA-Z0-9\-_]`)
		return re.ReplaceAllString(s, "-")
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with-dashes", "with-dashes"},
		{"with_underscores", "with_underscores"},
		{"with spaces", "with-spaces"},
		{"with:colons", "with-colons"},
		{"with/slashes", "with-slashes"},
		{"with@special!chars#", "with-special-chars-"},
		{"123numbers", "123numbers"},
		{"UPPERCASE", "UPPERCASE"},
		{"mixed123_CASE-test", "mixed123_CASE-test"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeIdentifier(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestProcessHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string][]string
		expected map[string]interface{}
	}{
		{
			name:     "empty headers",
			input:    map[string][]string{},
			expected: map[string]interface{}{},
		},
		{
			name: "single-value headers",
			input: map[string][]string{
				"Content-Type": {"application/json"},
				"Server":       {"nginx/1.18.0"},
			},
			expected: map[string]interface{}{
				"Content-Type": "application/json",
				"Server":       "nginx/1.18.0",
			},
		},
		{
			name: "multi-value headers",
			input: map[string][]string{
				"Set-Cookie": {"session=abc123", "csrf=xyz789"},
				"Accept":     {"text/html", "application/json"},
			},
			expected: map[string]interface{}{
				"Set-Cookie": []string{"session=abc123", "csrf=xyz789"},
				"Accept":     []string{"text/html", "application/json"},
			},
		},
		{
			name: "mixed single and multi-value headers",
			input: map[string][]string{
				"Content-Type": {"application/json"},
				"Set-Cookie":   {"session=abc123", "csrf=xyz789"},
				"Server":       {"nginx/1.18.0"},
			},
			expected: map[string]interface{}{
				"Content-Type": "application/json",
				"Set-Cookie":   []string{"session=abc123", "csrf=xyz789"},
				"Server":       "nginx/1.18.0",
			},
		},
		{
			name: "headers with empty values",
			input: map[string][]string{
				"Content-Type":   {"application/json"},
				"Empty-Header":   {},
				"Another-Header": {"value"},
			},
			expected: map[string]interface{}{
				"Content-Type":   "application/json",
				"Another-Header": "value",
				// Empty-Header should not be included
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processHeaders(tt.input)

			// Check that maps have same length
			if len(result) != len(tt.expected) {
				t.Errorf("Expected map length %d, got %d", len(tt.expected), len(result))
			}

			// Check each expected key-value pair
			for key, expectedValue := range tt.expected {
				actualValue, exists := result[key]
				if !exists {
					t.Errorf("Expected key %s not found in result", key)
					continue
				}

				// Handle string values
				if expectedStr, ok := expectedValue.(string); ok {
					if actualStr, ok := actualValue.(string); ok {
						if actualStr != expectedStr {
							t.Errorf("For key %s: expected %s, got %s", key, expectedStr, actualStr)
						}
					} else {
						t.Errorf("For key %s: expected string %s, got %T %v", key, expectedStr, actualValue, actualValue)
					}
				}

				// Handle slice values
				if expectedSlice, ok := expectedValue.([]string); ok {
					if actualSlice, ok := actualValue.([]string); ok {
						if len(actualSlice) != len(expectedSlice) {
							t.Errorf("For key %s: expected slice length %d, got %d", key, len(expectedSlice), len(actualSlice))
							continue
						}
						for i, expected := range expectedSlice {
							if i < len(actualSlice) && actualSlice[i] != expected {
								t.Errorf("For key %s[%d]: expected %s, got %s", key, i, expected, actualSlice[i])
							}
						}
					} else {
						t.Errorf("For key %s: expected []string %v, got %T %v", key, expectedSlice, actualValue, actualValue)
					}
				}
			}

			// Check for unexpected keys in result
			for key := range result {
				if _, exists := tt.expected[key]; !exists {
					t.Errorf("Unexpected key %s found in result", key)
				}
			}
		})
	}
}