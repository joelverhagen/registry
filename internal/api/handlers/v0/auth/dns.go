package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	v0 "github.com/modelcontextprotocol/registry/internal/api/handlers/v0"
	"github.com/modelcontextprotocol/registry/internal/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
)

// DNSTokenExchangeInput represents the input for DNS-based authentication
type DNSTokenExchangeInput struct {
	Body CoreTokenExchangeInput
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
	CoreAuthHandler
	resolver DNSResolver
}

// NewDNSAuthHandler creates a new DNS authentication handler
func NewDNSAuthHandler(cfg *config.Config) *DNSAuthHandler {
	return &DNSAuthHandler{
		CoreAuthHandler: *NewCoreAuthHandler(cfg),
		resolver:        &DefaultDNSResolver{},
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
	_, err := ValidateDomainAndTimestamp(domain, timestamp)
	if err != nil {
		return nil, err
	}

	signature, err := DecodeAndValidateSignature(signedTimestamp)
	if err != nil {
		return nil, err
	}

	// Lookup DNS TXT records
	txtRecords, err := h.resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup DNS TXT records: %w", err)
	}

	publicKeys := ParseMCPKeysFromStrings(txtRecords)

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no valid MCP public keys found in DNS TXT records")
	}

	messageBytes := []byte(timestamp)
	if !VerifySignatureWithKeys(publicKeys, messageBytes, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Build permissions for domain (DNS includes subdomains)
	permissions := BuildPermissions(domain, true)

	return h.CreateJWTClaimsAndToken(ctx, auth.MethodDNS, domain, permissions)
}
