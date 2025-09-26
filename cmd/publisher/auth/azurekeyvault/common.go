package azurekeyvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"fmt"
	"math/big"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/modelcontextprotocol/registry/cmd/publisher/auth"
)

func GetSignatureProvider(vaultURL, keyName string) (auth.Signer, error) {
	if vaultURL == "" {
		return nil, fmt.Errorf("--vault-url is required")
	}

	if keyName == "" {
		return nil, fmt.Errorf("--key-name is required")
	}

	u, err := url.ParseRequestURI(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("--vault-url must be a valid URL: %w", err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("--vault-url must be an HTTPS URL")
	}

	if len(u.Path) > 0 && u.Path != "/" {
		return nil, fmt.Errorf("--vault-url must not have a path, the key name must be specified in --key-name")
	}

	return AzureKeyVaultSigner{
		vaultURL: vaultURL,
		keyName:  keyName,
	}, nil
}

type AzureKeyVaultSigner struct {
	vaultURL string
	keyName  string
}

func (d AzureKeyVaultSigner) SignMessage(ctx context.Context, message []byte) ([]byte, error) {
	fmt.Printf("Signing using Azure Key Vault %s and key %s\n", d.vaultURL, d.keyName)

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	client, err := azkeys.NewClient(d.vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	keyResp, err := client.GetKey(ctx, d.keyName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve key for public parameters: %w", err)
	}

	if *keyResp.Key.Kty != azkeys.KeyTypeEC && *keyResp.Key.Kty != azkeys.KeyTypeECHSM {
		return nil, fmt.Errorf("unsupported key type: kty=%v (only EC keys are supported)", keyResp.Key.Kty)
	}

	if *keyResp.Key.Crv != azkeys.CurveNameP384 {
		return nil, fmt.Errorf("unsupported curve: crv=%v (only P-384 is supported)", keyResp.Key.Crv)
	}

	auth.PrintEcdsaKeyInfo("ecdsap384", ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     new(big.Int).SetBytes(keyResp.Key.X),
		Y:     new(big.Int).SetBytes(keyResp.Key.Y),
	})

	digest := sha512.Sum384(message)
	alg := azkeys.SignatureAlgorithmES384
	signResp, err := client.Sign(ctx, d.keyName, "", azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest[:],
	}, nil)

	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return signResp.Result, nil
}
