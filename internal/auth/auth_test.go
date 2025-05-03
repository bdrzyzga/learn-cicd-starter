package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey abc123")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "abc123" {
		t.Errorf("expected 'abc123', got '%s'", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer abc123") // wrong prefix

	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected 'malformed authorization header' error, got %v", err)
	}
}

func TestGetAPIKey_MissingKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey") // no actual key

	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected 'malformed authorization header' error, got %v", err)
	}
}
