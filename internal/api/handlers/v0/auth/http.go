package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	v0 "github.com/modelcontextprotocol/registry/internal/api/handlers/v0"
	"github.com/modelcontextprotocol/registry/internal/auth"
	"github.com/modelcontextprotocol/registry/internal/config"
)

// HTTPTokenExchangeInput represents the input for HTTP-based authentication
type HTTPTokenExchangeInput struct {
	Body CoreTokenExchangeInput
}

// HTTPKeyFetcher defines the interface for fetching HTTP keys
type HTTPKeyFetcher interface {
	FetchKey(ctx context.Context, domain string) (string, error)
}

// DefaultHTTPKeyFetcher uses Go's standard HTTP client
type DefaultHTTPKeyFetcher struct {
	client *http.Client
}

// NewDefaultHTTPKeyFetcher creates a new HTTP key fetcher with timeout
func NewDefaultHTTPKeyFetcher() *DefaultHTTPKeyFetcher {
	return &DefaultHTTPKeyFetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
			// Disable redirects for security purposes:
			// Prevents people doing weird things like sending us to internal endpoints at different paths
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// FetchKey fetches the public key from the well-known HTTP endpoint
func (f *DefaultHTTPKeyFetcher) FetchKey(ctx context.Context, domain string) (string, error) {
	url := fmt.Sprintf("https://%s/.well-known/mcp-registry-auth", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "mcp-registry/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: failed to fetch key from %s", resp.StatusCode, url)
	}

	// Limit response size to prevent DoS attacks
	resp.Body = http.MaxBytesReader(nil, resp.Body, 4096)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	return strings.TrimSpace(string(body)), nil
}

// HTTPAuthHandler handles HTTP-based authentication
type HTTPAuthHandler struct {
	CoreAuthHandler
	fetcher HTTPKeyFetcher
}

// NewHTTPAuthHandler creates a new HTTP authentication handler
func NewHTTPAuthHandler(cfg *config.Config) *HTTPAuthHandler {
	return &HTTPAuthHandler{
		CoreAuthHandler: *NewCoreAuthHandler(cfg),
		fetcher:         NewDefaultHTTPKeyFetcher(),
	}
}

// SetFetcher sets a custom HTTP key fetcher (used for testing)
func (h *HTTPAuthHandler) SetFetcher(fetcher HTTPKeyFetcher) {
	h.fetcher = fetcher
}

// RegisterHTTPEndpoint registers the HTTP authentication endpoint
func RegisterHTTPEndpoint(api huma.API, cfg *config.Config) {
	handler := NewHTTPAuthHandler(cfg)

	// HTTP authentication endpoint
	huma.Register(api, huma.Operation{
		OperationID: "exchange-http-token",
		Method:      http.MethodPost,
		Path:        "/v0/auth/http",
		Summary:     "Exchange HTTP signature for Registry JWT",
		Description: "Authenticate using HTTP-hosted public key and signed timestamp",
		Tags:        []string{"auth"},
	}, func(ctx context.Context, input *HTTPTokenExchangeInput) (*v0.Response[auth.TokenResponse], error) {
		response, err := handler.ExchangeToken(ctx, input.Body.Domain, input.Body.Timestamp, input.Body.SignedTimestamp)
		if err != nil {
			return nil, huma.Error401Unauthorized("HTTP authentication failed", err)
		}

		return &v0.Response[auth.TokenResponse]{
			Body: *response,
		}, nil
	})
}

// ExchangeToken exchanges HTTP signature for a Registry JWT token
func (h *HTTPAuthHandler) ExchangeToken(ctx context.Context, domain, timestamp, signedTimestamp string) (*auth.TokenResponse, error) {
	// Validate domain and timestamp using shared utility
	_, err := ValidateDomainAndTimestamp(domain, timestamp)
	if err != nil {
		return nil, err
	}

	// Decode and validate signature using shared utility
	signature, err := DecodeAndValidateSignature(signedTimestamp)
	if err != nil {
		return nil, err
	}

	// Fetch public key from HTTP endpoint
	keyResponse, err := h.fetcher.FetchKey(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}

	// Parse public key from HTTP response using shared utility
	publicKey, err := ParseMCPKeyFromString(keyResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Verify signature using shared utility
	messageBytes := []byte(timestamp)
	if !VerifySignatureWithKey(publicKey, messageBytes, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Build permissions for domain (HTTP does not include subdomains)
	permissions := BuildPermissions(domain, false)

	// Create JWT claims and token using shared utility
	return h.CreateJWTClaimsAndToken(ctx, auth.MethodHTTP, domain, permissions)
}


