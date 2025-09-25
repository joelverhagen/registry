package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/registry/internal/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
)

// CoreTokenExchangeInput represents the common input structure for token exchange
type CoreTokenExchangeInput struct {
	Domain          string `json:"domain" doc:"Domain name" example:"example.com" required:"true"`
	Timestamp       string `json:"timestamp" doc:"RFC3339 timestamp" example:"2023-01-01T00:00:00Z" required:"true"`
	SignedTimestamp string `json:"signed_timestamp" doc:"Hex-encoded Ed25519 signature of timestamp" example:"abcdef1234567890" required:"true"`
}

// CoreAuthHandler represents the common handler structure
type CoreAuthHandler struct {
	config     *config.Config
	jwtManager *auth.JWTManager
}

// NewCoreAuthHandler creates a new core authentication handler
func NewCoreAuthHandler(cfg *config.Config) *CoreAuthHandler {
	return &CoreAuthHandler{
		config:     cfg,
		jwtManager: auth.NewJWTManager(cfg),
	}
}

// ValidateDomainAndTimestamp validates the domain format and timestamp
func ValidateDomainAndTimestamp(domain, timestamp string) (*time.Time, error) {
	// Validate domain format
	if !IsValidDomain(domain) {
		return nil, fmt.Errorf("invalid domain format")
	}

	// Parse and validate timestamp
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp format: %w", err)
	}

	// Check timestamp is within 15 seconds
	now := time.Now()
	if ts.Before(now.Add(-15*time.Second)) || ts.After(now.Add(15*time.Second)) {
		return nil, fmt.Errorf("timestamp outside valid window (±15 seconds)")
	}

	return &ts, nil
}

// DecodeAndValidateSignature decodes and validates the signature format
func DecodeAndValidateSignature(signedTimestamp string) ([]byte, error) {
	// Decode signature
	signature, err := hex.DecodeString(signedTimestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format, must be hex: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	return signature, nil
}

// VerifySignatureWithKeys verifies signature against a list of public keys
func VerifySignatureWithKeys(publicKeys []ed25519.PublicKey, messageBytes []byte, signature []byte) bool {
	for _, publicKey := range publicKeys {
		if ed25519.Verify(publicKey, messageBytes, signature) {
			return true
		}
	}
	return false
}

// VerifySignatureWithKey verifies signature against a single public key
func VerifySignatureWithKey(publicKey ed25519.PublicKey, messageBytes []byte, signature []byte) bool {
	return ed25519.Verify(publicKey, messageBytes, signature)
}

// BuildPermissions builds permissions for a domain with optional subdomain support
func BuildPermissions(domain string, includeSubdomains bool) []auth.Permission {
	reverseDomain := ReverseString(domain)

	permissions := []auth.Permission{
		// Grant permissions for the exact domain (e.g., com.example/*)
		{
			Action:          auth.PermissionActionPublish,
			ResourcePattern: fmt.Sprintf("%s/*", reverseDomain),
		},
	}

	if includeSubdomains {
		// DNS implies a hierarchy where subdomains are treated as part of the parent domain,
		// therefore we grant permissions for all subdomains (e.g., com.example.*)
		// This is in line with other DNS-based authentication methods e.g. ACME DNS-01 challenges
		permissions = append(permissions, auth.Permission{
			Action:          auth.PermissionActionPublish,
			ResourcePattern: fmt.Sprintf("%s.*", reverseDomain),
		})
	}

	return permissions
}

// CreateJWTClaimsAndToken creates JWT claims and generates a token response
func (h *CoreAuthHandler) CreateJWTClaimsAndToken(ctx context.Context, authMethod auth.Method, domain string, permissions []auth.Permission) (*auth.TokenResponse, error) {
	// Create JWT claims
	jwtClaims := auth.JWTClaims{
		AuthMethod:        authMethod,
		AuthMethodSubject: domain,
		Permissions:       permissions,
	}

	// Generate Registry JWT token
	tokenResponse, err := h.jwtManager.GenerateTokenResponse(ctx, jwtClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT token: %w", err)
	}

	return tokenResponse, nil
}

// ParseMCPKeyFromString parses an Ed25519 public key from MCP format string
func ParseMCPKeyFromString(input string) (ed25519.PublicKey, error) {
	// Expected format: v=MCPv1; k=ed25519; p=<base64-encoded-key>
	mcpPattern := GetMCPKeyPattern()

	matches := mcpPattern.FindStringSubmatch(input)
	if len(matches) != 2 {
		return nil, fmt.Errorf("invalid key format, expected: v=MCPv1; k=ed25519; p=<base64-key>")
	}

	// Decode base64 public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(matches[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: expected %d, got %d", ed25519.PublicKeySize, len(publicKeyBytes))
	}

	return ed25519.PublicKey(publicKeyBytes), nil
}

// ParseMCPKeysFromStrings parses multiple Ed25519 public keys from MCP format strings
func ParseMCPKeysFromStrings(inputs []string) []ed25519.PublicKey {
	var publicKeys []ed25519.PublicKey
	mcpPattern := GetMCPKeyPattern()

	for _, input := range inputs {
		matches := mcpPattern.FindStringSubmatch(input)
		if len(matches) == 2 {
			// Decode base64 public key
			publicKeyBytes, err := base64.StdEncoding.DecodeString(matches[1])
			if err != nil {
				continue // Skip invalid keys
			}

			if len(publicKeyBytes) != ed25519.PublicKeySize {
				continue // Skip invalid key sizes
			}

			publicKeys = append(publicKeys, ed25519.PublicKey(publicKeyBytes))
		}
	}

	return publicKeys
}

// GetMCPKeyPattern returns the compiled regex pattern for MCP key format
func GetMCPKeyPattern() *regexp.Regexp {
	return regexp.MustCompile(`v=MCPv1;\s*k=ed25519;\s*p=([A-Za-z0-9+/=]+)`)
}

// IsValidDomain validates domain format
func IsValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters and structure
	domainPattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	return domainPattern.MatchString(domain)
}

// ReverseString reverses a domain string (example.com -> com.example)
func ReverseString(domain string) string {
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}