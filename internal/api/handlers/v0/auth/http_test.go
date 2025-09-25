package auth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/modelcontextprotocol/registry/internal/api/handlers/v0/auth"
	intauth "github.com/modelcontextprotocol/registry/internal/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
)

const testDomain = "example.com"

// MockHTTPKeyFetcher for testing
type MockHTTPKeyFetcher struct {
	keyResponses map[string]string
	err          error
}

func (m *MockHTTPKeyFetcher) FetchKey(_ context.Context, domain string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.keyResponses[domain], nil
}

func TestHTTPAuthHandler_ExchangeToken(t *testing.T) {
	cfg := &config.Config{
		JWTPrivateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	handler := auth.NewHTTPAuthHandler(cfg)

	// Generate a test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Create mock HTTP key fetcher
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	mockFetcher := &MockHTTPKeyFetcher{
		keyResponses: map[string]string{
			testDomain: fmt.Sprintf("v=MCPv1; k=ed25519; p=%s", publicKeyB64),
		},
	}
	handler.SetFetcher(mockFetcher)

	tests := []struct {
		name            string
		domain          string
		timestamp       string
		signedTimestamp string
		setupMock       func(*MockHTTPKeyFetcher)
		expectError     bool
		errorContains   string
	}{
		{
			name:      "successful authentication",
			domain:    testDomain,
			timestamp: time.Now().UTC().Format(time.RFC3339),
			setupMock: func(_ *MockHTTPKeyFetcher) {
				// Mock is already set up with valid key
			},
			expectError: false,
		},
		{
			name:          "invalid domain format",
			domain:        "invalid..domain",
			timestamp:     time.Now().UTC().Format(time.RFC3339),
			expectError:   true,
			errorContains: "invalid domain format",
		},
		{
			name:          "invalid timestamp format",
			domain:        testDomain,
			timestamp:     "invalid-timestamp",
			expectError:   true,
			errorContains: "invalid timestamp format",
		},
		{
			name:          "timestamp too old",
			domain:        testDomain,
			timestamp:     time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339),
			expectError:   true,
			errorContains: "timestamp outside valid window",
		},
		{
			name:          "timestamp too far in the future",
			domain:        testDomain,
			timestamp:     time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339),
			expectError:   true,
			errorContains: "timestamp outside valid window",
		},
		{
			name:            "invalid signature format",
			domain:          testDomain,
			timestamp:       time.Now().UTC().Format(time.RFC3339),
			signedTimestamp: "invalid-hex",
			expectError:     true,
			errorContains:   "invalid signature format",
		},
		{
			name:            "signature wrong length",
			domain:          testDomain,
			timestamp:       time.Now().UTC().Format(time.RFC3339),
			signedTimestamp: "abcdef", // too short
			expectError:     true,
			errorContains:   "invalid signature length",
		},
		{
			name:      "HTTP key fetch failure",
			domain:    "nonexistent.com",
			timestamp: time.Now().UTC().Format(time.RFC3339),
			setupMock: func(m *MockHTTPKeyFetcher) {
				m.err = fmt.Errorf("HTTP 404: not found")
			},
			expectError:   true,
			errorContains: "failed to fetch public key",
		},
		{
			name:      "invalid key format",
			domain:    "invalidkey.com",
			timestamp: time.Now().UTC().Format(time.RFC3339),
			setupMock: func(m *MockHTTPKeyFetcher) {
				m.keyResponses["invalidkey.com"] = "invalid key format"
				m.err = nil
			},
			expectError:   true,
			errorContains: "failed to parse public key",
		},
		{
			name:      "invalid base64 key",
			domain:    "badkey.com",
			timestamp: time.Now().UTC().Format(time.RFC3339),
			setupMock: func(m *MockHTTPKeyFetcher) {
				m.keyResponses["badkey.com"] = "v=MCPv1; k=ed25519; p=invalid-base64!!!"
				m.err = nil
			},
			expectError:   true,
			errorContains: "failed to parse public key",
		},
		{
			name:      "wrong key size",
			domain:    "wrongsize.com",
			timestamp: time.Now().UTC().Format(time.RFC3339),
			setupMock: func(m *MockHTTPKeyFetcher) {
				// Generate a key that's too short
				shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
				m.keyResponses["wrongsize.com"] = fmt.Sprintf("v=MCPv1; k=ed25519; p=%s", shortKey)
				m.err = nil
			},
			expectError:   true,
			errorContains: "failed to parse public key",
		},
		{
			name:      "signature verification failure",
			domain:    testDomain,
			timestamp: time.Now().UTC().Format(time.RFC3339),
			setupMock: func(m *MockHTTPKeyFetcher) {
				// Generate different key pair for signature verification failure
				wrongPublicKey, _, err := ed25519.GenerateKey(nil)
				require.NoError(t, err)
				wrongPublicKeyB64 := base64.StdEncoding.EncodeToString(wrongPublicKey)
				m.keyResponses[testDomain] = fmt.Sprintf("v=MCPv1; k=ed25519; p=%s", wrongPublicKeyB64)
				m.err = nil
			},
			expectError:   true,
			errorContains: "signature verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock fetcher
			mockFetcher.err = nil
			if tt.setupMock != nil {
				tt.setupMock(mockFetcher)
			}

			// Generate signature if not provided
			signedTimestamp := tt.signedTimestamp
			if signedTimestamp == "" {
				// Generate a valid signature for all cases
				signature := ed25519.Sign(privateKey, []byte(tt.timestamp))
				signedTimestamp = hex.EncodeToString(signature)
			}

			// Call the handler
			result, err := handler.ExchangeToken(context.Background(), tt.domain, tt.timestamp, signedTimestamp)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result.RegistryToken)

				// Verify the token contains expected claims
				jwtManager := intauth.NewJWTManager(cfg)
				claims, err := jwtManager.ValidateToken(context.Background(), result.RegistryToken)
				require.NoError(t, err)

				assert.Equal(t, intauth.MethodHTTP, claims.AuthMethod)
				assert.Equal(t, tt.domain, claims.AuthMethodSubject)
				assert.Len(t, claims.Permissions, 1) // domain permissions only

				// Check permissions use reverse DNS patterns
				patterns := make([]string, len(claims.Permissions))
				for i, perm := range claims.Permissions {
					patterns[i] = perm.ResourcePattern
				}
				// Convert domain to reverse DNS for expected patterns
				parts := strings.Split(tt.domain, ".")
				for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
					parts[i], parts[j] = parts[j], parts[i]
				}
				reverseDomain := strings.Join(parts, ".")
				assert.Contains(t, patterns, fmt.Sprintf("%s/*", reverseDomain))
			}
		})
	}
}

func TestDefaultHTTPKeyFetcher_FetchKey(t *testing.T) {
	// This test would require a real HTTP server or more sophisticated mocking
	// For now, we'll test the basic structure
	fetcher := auth.NewDefaultHTTPKeyFetcher()
	assert.NotNil(t, fetcher)

	// Test that it returns an error for non-existent domains
	// (This will fail with network error, which is expected)
	_, err := fetcher.FetchKey(context.Background(), "nonexistent-test-domain-12345.com")
	assert.Error(t, err)
}

func TestHTTPAuthHandler_Permissions(t *testing.T) {
	cfg := &config.Config{
		JWTPrivateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	handler := auth.NewHTTPAuthHandler(cfg)
	jwtManager := intauth.NewJWTManager(cfg)

	// Generate a test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)

	tests := []struct {
		name               string
		domain             string
		expectedPatterns   []string
		unexpectedPatterns []string
	}{
		{
			name:   "simple domain",
			domain: testDomain,
			expectedPatterns: []string{
				"com.example/*", // exact domain pattern only (HTTP does not include subdomains)
			},
			unexpectedPatterns: []string{
				"com.example.*", // HTTP should not grant subdomain permissions
				"example.com/*", // should be reversed
				"*.com.example", // wrong wildcard position
			},
		},
		{
			name:   "subdomain",
			domain: "api.example.com",
			expectedPatterns: []string{
				"com.example.api/*", // exact subdomain pattern only
			},
			unexpectedPatterns: []string{
				"com.example.api.*", // HTTP should not grant subdomain permissions
				"com.example/*",     // parent domain should not be included
				"api.example.com/*", // should be reversed
			},
		},
		{
			name:   "multi-level subdomain",
			domain: "v1.api.example.com",
			expectedPatterns: []string{
				"com.example.api.v1/*", // exact pattern only
			},
			unexpectedPatterns: []string{
				"com.example.api.v1.*", // HTTP should not grant subdomain permissions
				"com.example/*",        // parent domain should not be included
				"com.example.api/*",    // intermediate domain should not be included
				"v1.api.example.com/*", // should be reversed
			},
		},
		{
			name:   "single part domain",
			domain: "localhost",
			expectedPatterns: []string{
				"localhost/*", // exact pattern only (no reversal needed)
			},
			unexpectedPatterns: []string{
				"localhost.*", // HTTP should not grant subdomain permissions
				"*.localhost", // wrong wildcard position
			},
		},
		{
			name:   "hyphenated domain",
			domain: "my-app.example-site.com",
			expectedPatterns: []string{
				"com.example-site.my-app/*", // exact pattern only
			},
			unexpectedPatterns: []string{
				"com.example-site.my-app.*", // HTTP should not grant subdomain permissions
				"my-app.example-site.com/*", // should be reversed
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mock fetcher
			mockFetcher := &MockHTTPKeyFetcher{
				keyResponses: map[string]string{
					tt.domain: fmt.Sprintf("v=MCPv1; k=ed25519; p=%s", publicKeyB64),
				},
			}
			handler.SetFetcher(mockFetcher)

			// Generate signature
			timestamp := time.Now().UTC().Format(time.RFC3339)
			signature := ed25519.Sign(privateKey, []byte(timestamp))
			signedTimestamp := hex.EncodeToString(signature)

			// Exchange token
			result, err := handler.ExchangeToken(context.Background(), tt.domain, timestamp, signedTimestamp)
			require.NoError(t, err)
			require.NotNil(t, result)

			// Validate JWT token
			claims, err := jwtManager.ValidateToken(context.Background(), result.RegistryToken)
			require.NoError(t, err)

			// Verify claims structure
			assert.Equal(t, intauth.MethodHTTP, claims.AuthMethod)
			assert.Equal(t, tt.domain, claims.AuthMethodSubject)
			assert.Len(t, claims.Permissions, 1) // HTTP only grants exact domain permissions

			// Extract permission patterns
			patterns := make([]string, len(claims.Permissions))
			for i, perm := range claims.Permissions {
				patterns[i] = perm.ResourcePattern
				// All permissions should be for publish action
				assert.Equal(t, intauth.PermissionActionPublish, perm.Action)
			}

			// Check expected patterns are present
			for _, expectedPattern := range tt.expectedPatterns {
				assert.Contains(t, patterns, expectedPattern, "Expected pattern %s not found", expectedPattern)
			}

			// Check unexpected patterns are not present
			for _, unexpectedPattern := range tt.unexpectedPatterns {
				assert.NotContains(t, patterns, unexpectedPattern, "Unexpected pattern %s found", unexpectedPattern)
			}

			// Verify the permission patterns work correctly with the JWT manager's HasPermission method
			for _, expectedPattern := range tt.expectedPatterns {
				// Find the permission with this pattern
				var foundPerm *intauth.Permission
				for _, perm := range claims.Permissions {
					if perm.ResourcePattern == expectedPattern {
						foundPerm = &perm
						break
					}
				}
				require.NotNil(t, foundPerm, "Permission with pattern %s not found", expectedPattern)

				// Test resource scenarios - only exact domain should work for HTTP
				if strings.HasSuffix(expectedPattern, "/*") {
					// Exact domain permissions (e.g., "com.example/*")
					basePattern := strings.TrimSuffix(expectedPattern, "/*")
					testResource := basePattern + "/my-package"
					assert.True(t, jwtManager.HasPermission(testResource, intauth.PermissionActionPublish, claims.Permissions),
						"Should have permission for %s with pattern %s", testResource, expectedPattern)

					// Test that subdomain resources are NOT allowed for HTTP
					subdomainResource := basePattern + ".subdomain/my-package"
					assert.False(t, jwtManager.HasPermission(subdomainResource, intauth.PermissionActionPublish, claims.Permissions),
						"Should NOT have permission for subdomain %s with HTTP auth", subdomainResource)
				}
			}
		})
	}
}

func TestHTTPAuthHandler_PermissionValidation(t *testing.T) {
	cfg := &config.Config{
		JWTPrivateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	handler := auth.NewHTTPAuthHandler(cfg)
	jwtManager := intauth.NewJWTManager(cfg)

	// Generate a test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	domain := testDomain

	// Set up mock fetcher
	mockFetcher := &MockHTTPKeyFetcher{
		keyResponses: map[string]string{
			domain: fmt.Sprintf("v=MCPv1; k=ed25519; p=%s", publicKeyB64),
		},
	}
	handler.SetFetcher(mockFetcher)

	// Generate signature and exchange token
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := ed25519.Sign(privateKey, []byte(timestamp))
	signedTimestamp := hex.EncodeToString(signature)

	result, err := handler.ExchangeToken(context.Background(), domain, timestamp, signedTimestamp)
	require.NoError(t, err)

	claims, err := jwtManager.ValidateToken(context.Background(), result.RegistryToken)
	require.NoError(t, err)

	// Test permission validation scenarios
	testCases := []struct {
		name       string
		resource   string
		action     intauth.PermissionAction
		shouldPass bool
	}{
		{
			name:       "exact domain resource with publish action",
			resource:   "com.example/my-package",
			action:     intauth.PermissionActionPublish,
			shouldPass: true,
		},
		{
			name:       "subdomain resource should fail for HTTP",
			resource:   "com.example.api/my-package",
			action:     intauth.PermissionActionPublish,
			shouldPass: false, // HTTP does not grant subdomain permissions
		},
		{
			name:       "deep subdomain resource should fail for HTTP",
			resource:   "com.example.v1.api/my-package",
			action:     intauth.PermissionActionPublish,
			shouldPass: false, // HTTP does not grant subdomain permissions
		},
		{
			name:       "different domain should fail",
			resource:   "com.otherdomain/my-package",
			action:     intauth.PermissionActionPublish,
			shouldPass: false,
		},
		{
			name:       "partial domain match should fail",
			resource:   "com.example-other/my-package",
			action:     intauth.PermissionActionPublish,
			shouldPass: false,
		},
		{
			name:       "parent domain should fail",
			resource:   "com/my-package",
			action:     intauth.PermissionActionPublish,
			shouldPass: false,
		},
		{
			name:       "edit action should fail (not granted)",
			resource:   "com.example/my-package",
			action:     intauth.PermissionActionEdit,
			shouldPass: false,
		},
		{
			name:       "resource without package separator should fail",
			resource:   "com.example",
			action:     intauth.PermissionActionPublish,
			shouldPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hasPermission := jwtManager.HasPermission(tc.resource, tc.action, claims.Permissions)
			if tc.shouldPass {
				assert.True(t, hasPermission, "Expected permission for resource %s with action %s", tc.resource, tc.action)
			} else {
				assert.False(t, hasPermission, "Expected no permission for resource %s with action %s", tc.resource, tc.action)
			}
		})
	}
}

func TestHTTPvsDNS_PermissionDifferences(t *testing.T) {
	cfg := &config.Config{
		JWTPrivateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	httpHandler := auth.NewHTTPAuthHandler(cfg)
	dnsHandler := auth.NewDNSAuthHandler(cfg)
	jwtManager := intauth.NewJWTManager(cfg)

	// Generate a test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey)
	domain := testDomain

	// Set up mocks
	mockFetcher := &MockHTTPKeyFetcher{
		keyResponses: map[string]string{
			domain: fmt.Sprintf("v=MCPv1; k=ed25519; p=%s", publicKeyB64),
		},
	}
	httpHandler.SetFetcher(mockFetcher)

	mockResolver := &MockDNSResolver{
		txtRecords: map[string][]string{
			domain: {
				fmt.Sprintf("v=MCPv1; k=ed25519; p=%s", publicKeyB64),
			},
		},
	}
	dnsHandler.SetResolver(mockResolver)

	// Generate tokens from both handlers
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := ed25519.Sign(privateKey, []byte(timestamp))
	signedTimestamp := hex.EncodeToString(signature)

	httpResult, err := httpHandler.ExchangeToken(context.Background(), domain, timestamp, signedTimestamp)
	require.NoError(t, err)

	dnsResult, err := dnsHandler.ExchangeToken(context.Background(), domain, timestamp, signedTimestamp)
	require.NoError(t, err)

	// Validate both tokens
	httpClaims, err := jwtManager.ValidateToken(context.Background(), httpResult.RegistryToken)
	require.NoError(t, err)

	dnsClaims, err := jwtManager.ValidateToken(context.Background(), dnsResult.RegistryToken)
	require.NoError(t, err)

	// Compare permission counts
	assert.Len(t, httpClaims.Permissions, 1, "HTTP should grant 1 permission (exact domain only)")
	assert.Len(t, dnsClaims.Permissions, 2, "DNS should grant 2 permissions (exact domain + subdomains)")

	// Test resources that should behave differently
	testCases := []struct {
		name        string
		resource    string
		httpAllowed bool
		dnsAllowed  bool
	}{
		{
			name:        "exact domain resource",
			resource:    "com.example/my-package",
			httpAllowed: true,
			dnsAllowed:  true,
		},
		{
			name:        "subdomain resource",
			resource:    "com.example.api/my-package",
			httpAllowed: false, // HTTP does not grant subdomain permissions
			dnsAllowed:  true,  // DNS grants subdomain permissions
		},
		{
			name:        "deep subdomain resource",
			resource:    "com.example.v1.api/my-package",
			httpAllowed: false, // HTTP does not grant subdomain permissions
			dnsAllowed:  true,  // DNS grants subdomain permissions
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			httpPermission := jwtManager.HasPermission(tc.resource, intauth.PermissionActionPublish, httpClaims.Permissions)
			dnsPermission := jwtManager.HasPermission(tc.resource, intauth.PermissionActionPublish, dnsClaims.Permissions)

			assert.Equal(t, tc.httpAllowed, httpPermission, "HTTP permission mismatch for %s", tc.resource)
			assert.Equal(t, tc.dnsAllowed, dnsPermission, "DNS permission mismatch for %s", tc.resource)
		})
	}
}
