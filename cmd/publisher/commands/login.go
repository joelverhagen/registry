package commands

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/registry/cmd/publisher/auth"
	"github.com/modelcontextprotocol/registry/cmd/publisher/auth/azurekeyvault"
	"github.com/modelcontextprotocol/registry/cmd/publisher/auth/googlekms"
)

const (
	DefaultRegistryURL = "https://registry.modelcontextprotocol.io"
	TokenFileName      = ".mcp_publisher_token" //nolint:gosec // Not a credential, just a filename
)

type CryptoAlgorithm auth.CryptoAlgorithm

type SignerType string

const (
	NoSignerType            SignerType = "no-signer"
	InProcessSignerType     SignerType = "in-process"
	AzureKeyVaultSignerType SignerType = "azure-key-vault"
	GoogleKMSSignerType     SignerType = "google-kms"
)

func (c *CryptoAlgorithm) String() string {
	return string(*c)
}

func (c *CryptoAlgorithm) Set(v string) error {
	switch v {
	case string(auth.AlgorithmEd25519), string(auth.AlgorithmECDSAP384):
		*c = CryptoAlgorithm(v)
		return nil
	}
	return fmt.Errorf("invalid algorithm: %q (allowed: ed25519, ecdsap384)", v)
}

func LoginCommand(args []string) error {
	if len(args) < 1 {
		return errors.New(`authentication method required

Usage: mcp-publisher login <method> [<signing provider>]

Methods:
  github            Interactive GitHub authentication
  github-oidc       GitHub Actions OIDC authentication
  dns               DNS-based authentication (requires --domain)
  http              HTTP-based authentication (requires --domain)
  none              Anonymous authentication (for testing)

Signing providers:
  azure-key-vault   Sign using Azure Key Vault
  google-kms        Sign using Google Cloud KMS

The dns and http methods require a --private-key for in-process signing. For
out-of-process signing, use one of the supported signing providers. Signing is
needed for an authentication challenge with the registry.

The github and github-oidc methods do not support signing providers and
authenticate using the GitHub as an identity provider.

  `)
	}

	method := args[0]

	// Parse remaining flags based on method
	loginFlags := flag.NewFlagSet("login", flag.ExitOnError)
	var domain string
	var privateKey string
	var cryptoAlgorithm CryptoAlgorithm = CryptoAlgorithm(auth.AlgorithmEd25519)
	var registryURL string
	var kvVault string
	var kvKeyName string
	var kmsResource string
	var signerType SignerType = NoSignerType
	var argOffset int = 1

	loginFlags.StringVar(&registryURL, "registry", DefaultRegistryURL, "Registry URL")

	if method == "dns" || method == "http" {
		loginFlags.StringVar(&domain, "domain", "", "Domain name")

		if len(args) > 1 {
			switch args[1] {
			case string(AzureKeyVaultSignerType):
				signerType = AzureKeyVaultSignerType
				loginFlags.StringVar(&kvVault, "vault", "", "The name of the Azure Key Vault resource")
				loginFlags.StringVar(&kvKeyName, "key", "", "Name of the signing key in the Azure Key Vault")
				argOffset = 2
			case string(GoogleKMSSignerType):
				signerType = GoogleKMSSignerType
				loginFlags.StringVar(&kmsResource, "resource", "", "Google Cloud KMS resource name (e.g. projects/lotr/locations/global/keyRings/fellowship/cryptoKeys/frodo/cryptoKeyVersions/1)")
				argOffset = 2
			}
		}

		if signerType == NoSignerType {
			signerType = InProcessSignerType
			loginFlags.StringVar(&privateKey, "private-key", "", "Private key (hex)")
			loginFlags.Var(&cryptoAlgorithm, "algorithm", "Cryptographic algorithm (ed25519, ecdsap384)")
		}
	}

	if err := loginFlags.Parse(args[argOffset:]); err != nil {
		return err
	}

	var signer auth.Signer
	var err error
	switch signerType {
	case AzureKeyVaultSignerType:
		signer, err = azurekeyvault.GetSignatureProvider(kvVault, kvKeyName)
		if err != nil {
			return err
		}
	case GoogleKMSSignerType:
		signer, err = googlekms.GetSignatureProvider(kmsResource)
		if err != nil {
			return err
		}
	case InProcessSignerType:
		signer, err = auth.NewInProcessSigner(privateKey, auth.CryptoAlgorithm(cryptoAlgorithm))
		if err != nil {
			return err
		}
	}

	// Create auth provider based on method
	var authProvider auth.Provider
	switch method {
	case "github":
		authProvider = auth.NewGitHubATProvider(true, registryURL)
	case "github-oidc":
		authProvider = auth.NewGitHubOIDCProvider(registryURL)
	case "dns":
		if domain == "" {
			return errors.New("dns authentication requires --domain")
		}
		authProvider = auth.NewDNSProvider(registryURL, domain, &signer)
	case "http":
		if domain == "" {
			return errors.New("http authentication requires --domain")
		}
		authProvider = auth.NewHTTPProvider(registryURL, domain, &signer)
	case "none":
		authProvider = auth.NewNoneProvider(registryURL)
	default:
		return fmt.Errorf("unknown authentication method: %s\nFor a list of available methods, run: mcp-publisher login", method)
	}

	// Perform login
	ctx := context.Background()
	_, _ = fmt.Fprintf(os.Stdout, "Logging in with %s...\n", method)

	if err := authProvider.Login(ctx); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	// Get and save token
	token, err := authProvider.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Save token to file
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	tokenPath := filepath.Join(homeDir, TokenFileName)
	tokenData := map[string]string{
		"token":    token,
		"method":   method,
		"registry": registryURL,
	}

	jsonData, err := json.Marshal(tokenData)
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %w", err)
	}

	if err := os.WriteFile(tokenPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	_, _ = fmt.Fprintln(os.Stdout, "✓ Successfully logged in")
	return nil
}
