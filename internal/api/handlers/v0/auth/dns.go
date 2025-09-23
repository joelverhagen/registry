package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	v0 "github.com/modelcontextprotocol/registry/internal/api/handlers/v0"
	"github.com/modelcontextprotocol/registry/internal/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
)

// CryptoAlgorithm represents the cryptographic algorithm used for a public key
type CryptoAlgorithm string

const (
	AlgorithmEd25519 CryptoAlgorithm = "ed25519"

	// ECDSA with NIST P-384 curve
	// public key is in compressed format
	// signature is in R || S format
	AlgorithmECDSAP384 CryptoAlgorithm = "ecdsap384"
)

// PublicKeyInfo contains a public key along with its algorithm type
type PublicKeyInfo struct {
	Algorithm CryptoAlgorithm
	Key       any
}

// DNSTokenExchangeInput represents the input for DNS-based authentication
type DNSTokenExchangeInput struct {
	Body struct {
		Domain          string `json:"domain" doc:"Domain name" example:"example.com" required:"true"`
		Timestamp       string `json:"timestamp" doc:"RFC3339 timestamp" example:"2023-01-01T00:00:00Z" required:"true"`
		SignedTimestamp string `json:"signed_timestamp" doc:"Hex-encoded Ed25519 signature of timestamp" example:"abcdef1234567890" required:"true"`
	}
}

// DNSResolver defines the interface for DNS resolution
type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// DefaultDNSResolver uses Go's standard DNS resolution
type DefaultDNSResolver struct{}

// LookupTXT performs DNS TXT record lookup
func (r *DefaultDNSResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return (&net.Resolver{}).LookupTXT(ctx, name)
}

// DNSAuthHandler handles DNS-based authentication
type DNSAuthHandler struct {
	config     *config.Config
	jwtManager *auth.JWTManager
	resolver   DNSResolver
}

// NewDNSAuthHandler creates a new DNS authentication handler
func NewDNSAuthHandler(cfg *config.Config) *DNSAuthHandler {
	return &DNSAuthHandler{
		config:     cfg,
		jwtManager: auth.NewJWTManager(cfg),
		resolver:   &DefaultDNSResolver{},
	}
}

// SetResolver sets a custom DNS resolver (used for testing)
func (h *DNSAuthHandler) SetResolver(resolver DNSResolver) {
	h.resolver = resolver
}

// RegisterDNSEndpoint registers the DNS authentication endpoint
func RegisterDNSEndpoint(api huma.API, cfg *config.Config) {
	handler := NewDNSAuthHandler(cfg)

	// DNS authentication endpoint
	huma.Register(api, huma.Operation{
		OperationID: "exchange-dns-token",
		Method:      http.MethodPost,
		Path:        "/v0/auth/dns",
		Summary:     "Exchange DNS signature for Registry JWT",
		Description: "Authenticate using DNS TXT record public key and signed timestamp",
		Tags:        []string{"auth"},
	}, func(ctx context.Context, input *DNSTokenExchangeInput) (*v0.Response[auth.TokenResponse], error) {
		response, err := handler.ExchangeToken(ctx, input.Body.Domain, input.Body.Timestamp, input.Body.SignedTimestamp)
		if err != nil {
			return nil, huma.Error401Unauthorized("DNS authentication failed", err)
		}

		return &v0.Response[auth.TokenResponse]{
			Body: *response,
		}, nil
	})
}

// ExchangeToken exchanges DNS signature for a Registry JWT token
func (h *DNSAuthHandler) ExchangeToken(ctx context.Context, domain, timestamp, signedTimestamp string) (*auth.TokenResponse, error) {
	// Validate domain format
	if !isValidDomain(domain) {
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

	// Decode signature
	signature, err := hex.DecodeString(signedTimestamp)
	if err != nil {
		return nil, fmt.Errorf("invalid signature format, must be hex: %w", err)
	}

	if len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: expected %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Lookup DNS TXT records
	txtRecords, err := h.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup DNS TXT records: %w", err)
	}

	// Parse public keys from TXT records
	publicKeys := h.parsePublicKeysFromTXT(txtRecords)

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no valid MCP public keys found in DNS TXT records")
	}

	// Verify signature with any of the public keys
	messageBytes := []byte(timestamp)
	signatureValid := false
	for _, publicKeyInfo := range publicKeys {
		if publicKeyInfo.VerifySignature(messageBytes, signature) {
			signatureValid = true
			break
		}
	}

	if !signatureValid {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Build permissions for domain and subdomains
	permissions := h.buildPermissions(domain)

	// Create JWT claims
	jwtClaims := auth.JWTClaims{
		AuthMethod:        auth.MethodDNS,
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

// parsePublicKeysFromTXT parses public keys from DNS TXT records supporting multiple algorithms
func (h *DNSAuthHandler) parsePublicKeysFromTXT(txtRecords []string) []PublicKeyInfo {
	var publicKeys []PublicKeyInfo

	// TXT record pattern: v=MCPv1; k=<algo>; p=<base64-public-key>
	cryptoPattern := regexp.MustCompile(`v=MCPv1;\s*k=([^;]+);\s*p=([A-Za-z0-9+/=]+)`)

	for _, record := range txtRecords {
		if matches := cryptoPattern.FindStringSubmatch(record); len(matches) == 3 {
			// Decode base64 public key
			publicKeyBytes, err := base64.StdEncoding.DecodeString(matches[2])
			if err != nil {
				continue // Skip invalid keys
			}

			// match to a supported crypto algorithm
			switch matches[1] {
			case "ed25519":
				if len(publicKeyBytes) != ed25519.PublicKeySize {
					continue // Skip invalid key sizes
				}
				publicKeys = append(publicKeys, PublicKeyInfo{
					Algorithm: AlgorithmEd25519,
					Key:       ed25519.PublicKey(publicKeyBytes),
				})
			case "ecdsap384":
				if len(publicKeyBytes) != 49 || (publicKeyBytes[0] != 0x02 && publicKeyBytes[0] != 0x03) {
					continue // Skip uncompressed ECDSA P-384 keys
				}
				curve := elliptic.P384()
				x, y := elliptic.UnmarshalCompressed(curve, publicKeyBytes)
				if x == nil || y == nil {
					continue // Skip invalid keys
				}
				publicKeys = append(publicKeys, PublicKeyInfo{
					Algorithm: AlgorithmECDSAP384,
					Key:       ecdsa.PublicKey{Curve: curve, X: x, Y: y},
				})
			}
		}
	}

	return publicKeys
}

// VerifySignature verifies a signature using the appropriate algorithm
func (pki *PublicKeyInfo) VerifySignature(message, signature []byte) bool {
	switch pki.Algorithm {
	case AlgorithmEd25519:
		if ed25519Key, ok := pki.Key.(ed25519.PublicKey); ok {
			if len(signature) != ed25519.SignatureSize {
				return false
			}
			return ed25519.Verify(ed25519Key, message, signature)
		}
	case AlgorithmECDSAP384:
		if ecdsaKey, ok := pki.Key.(ecdsa.PublicKey); ok {
			if len(signature) != 96 {
				return false
			}
			r := new(big.Int).SetBytes(signature[:48])
			s := new(big.Int).SetBytes(signature[48:])
			return ecdsa.Verify(&ecdsaKey, message, r, s)
		}
	}
	return false
}

// buildPermissions builds permissions for a domain and its subdomains using reverse DNS notation
func (h *DNSAuthHandler) buildPermissions(domain string) []auth.Permission {
	reverseDomain := reverseString(domain)

	permissions := []auth.Permission{
		// Grant permissions for the exact domain (e.g., com.example/*)
		{
			Action:          auth.PermissionActionPublish,
			ResourcePattern: fmt.Sprintf("%s/*", reverseDomain),
		},
		// DNS implies a hierarchy where subdomains are treated as part of the parent domain,
		// therefore we grant permissions for all subdomains (e.g., com.example.*)
		// This is in line with other DNS-based authentication methods e.g. ACME DNS-01 challenges
		{
			Action:          auth.PermissionActionPublish,
			ResourcePattern: fmt.Sprintf("%s.*", reverseDomain),
		},
	}

	return permissions
}

// reverseString reverses a domain string (example.com -> com.example)
func reverseString(domain string) string {
	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters and structure
	domainPattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)
	return domainPattern.MatchString(domain)
}
