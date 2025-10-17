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

type LoginFlags struct {
	Domain          string
	PrivateKey      string
	RegistryURL     string
	KvVault         string
	KvKeyName       string
	KmsResource     string
	CryptoAlgorithm CryptoAlgorithm
	SignerType      SignerType
	ArgOffset       int
}

const (
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

func parseLoginFlags(method string, args []string) (LoginFlags, error) {
	var flags LoginFlags
	loginFlags := flag.NewFlagSet("login", flag.ExitOnError)
	flags.CryptoAlgorithm = CryptoAlgorithm(auth.AlgorithmEd25519)
	flags.SignerType = ""
	flags.ArgOffset = 1
	loginFlags.StringVar(&flags.RegistryURL, "registry", DefaultRegistryURL, "Registry URL")

	if method == "dns" || method == "http" {
		loginFlags.StringVar(&flags.Domain, "domain", "", "Domain name")
		if len(args) > 1 {
			switch args[1] {
			case string(AzureKeyVaultSignerType):
				flags.SignerType = AzureKeyVaultSignerType
				loginFlags.StringVar(&flags.KvVault, "vault", "", "The name of the Azure Key Vault resource")
				loginFlags.StringVar(&flags.KvKeyName, "key", "", "Name of the signing key in the Azure Key Vault")
				flags.ArgOffset = 2
			case string(GoogleKMSSignerType):
				flags.SignerType = GoogleKMSSignerType
				loginFlags.StringVar(&flags.KmsResource, "resource", "", "Google Cloud KMS resource name (e.g. projects/lotr/locations/global/keyRings/fellowship/cryptoKeys/frodo/cryptoKeyVersions/1)")
				flags.ArgOffset = 2
			}
		}
		if flags.SignerType == "" {
			flags.SignerType = InProcessSignerType
			loginFlags.StringVar(&flags.PrivateKey, "private-key", "", "Private key (hex)")
			loginFlags.Var(&flags.CryptoAlgorithm, "algorithm", "Cryptographic algorithm (ed25519, ecdsap384)")
		}
	}
	err := loginFlags.Parse(args[flags.ArgOffset:])
	return flags, err
}

func createSigner(flags LoginFlags) (auth.Signer, error) {
	switch flags.SignerType {
	case AzureKeyVaultSignerType:
		return azurekeyvault.GetSignatureProvider(flags.KvVault, flags.KvKeyName)
	case GoogleKMSSignerType:
		return googlekms.GetSignatureProvider(flags.KmsResource)
	case InProcessSignerType:
		return auth.NewInProcessSigner(flags.PrivateKey, auth.CryptoAlgorithm(flags.CryptoAlgorithm))
	}
	return nil, errors.New("no signing provider specified")
}

func createAuthProvider(method, registryURL, domain string, signer auth.Signer) (auth.Provider, error) {
	switch method {
	case "github":
		return auth.NewGitHubATProvider(true, registryURL), nil
	case "github-oidc":
		return auth.NewGitHubOIDCProvider(registryURL), nil
	case "dns":
		if domain == "" {
			return nil, errors.New("dns authentication requires --domain")
		}
		return auth.NewDNSProvider(registryURL, domain, &signer), nil
	case "http":
		if domain == "" {
			return nil, errors.New("http authentication requires --domain")
		}
		return auth.NewHTTPProvider(registryURL, domain, &signer), nil
	case "none":
		return auth.NewNoneProvider(registryURL), nil
	default:
		return nil, fmt.Errorf("unknown authentication method: %s\nFor a list of available methods, run: mcp-publisher login", method)
	}
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
	flags, err := parseLoginFlags(method, args)
	if err != nil {
		return err
	}

	signer, err := createSigner(flags)
	if err != nil {
		return err
	}

	authProvider, err := createAuthProvider(method, flags.RegistryURL, flags.Domain, signer)
	if err != nil {
		return err
	}

	ctx := context.Background()
	_, _ = fmt.Fprintf(os.Stdout, "Logging in with %s...\n", method)

	if err := authProvider.Login(ctx); err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	token, err := authProvider.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	tokenPath := filepath.Join(homeDir, TokenFileName)
	tokenData := map[string]string{
		"token":    token,
		"method":   method,
		"registry": flags.RegistryURL,
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
