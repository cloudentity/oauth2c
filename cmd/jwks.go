package cmd

import (
	"os"

	"github.com/cloudentity/oauth2c/internal/jwks"
	"github.com/go-jose/go-jose/v3"
	"github.com/spf13/cobra"
)

var jwksCmd = &cobra.Command{
	Use:   "jwks",
	Short: "JWKs operations",
}

var jwksConfig jwks.Config

var generateJwkCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate JWK",
	Long: `
# Supported algorithms

Signing                   | Algorithm
------------------------- | -------------------------
RSASSA-PKCS#1v1.5         | RS256, RS384, RS512
RSASSA-PSS                | PS256, PS384, PS512
ECDSA                     | ES256, ES384, ES512

Encryption                | Algorithm
------------------------- | -------------------------
RSA-PKCS#1v1.5            | RSA1_5
RSA-OAEP                  | RSA-OAEP, RSA-OAEP-256
ECDH-ES                   | ECDH-ES
ECDH-ES + AES key wrap    | ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW
`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			jwk jose.JSONWebKey
			err error
		)

		if jwk, err = jwks.Generate(jwksConfig); err != nil {
			LogError(err)
			os.Exit(1)
		}

		LogHeader("Generate JWK")

		LogSection("Private JWK")
		LogJson(jwk)

		LogSection("Public JWK")
		LogJson(jwk.Public())

		LogSection("Private Key")
		LogKey(jwk.Key)

		LogSection("Public Key")
		LogKey(jwk.Public().Key)
	},
}

func init() {
	generateJwkCmd.Flags().StringVar(&jwksConfig.Type, "type", "rsa", "key type (rsa, ec)")
	generateJwkCmd.Flags().StringVar(&jwksConfig.Alg, "alg", "", "key algorithm")
	generateJwkCmd.Flags().IntVar(&jwksConfig.Size, "size", 2048, "key size (2048, 3072, 4096)")
	generateJwkCmd.Flags().IntVar(&jwksConfig.Curve, "curve", 256, "key curve (224, 256, 384, 521)")
	generateJwkCmd.Flags().StringVar(&jwksConfig.Use, "use", "sig", "key use (sig, enc)")

	jwksCmd.AddCommand(generateJwkCmd)
}
