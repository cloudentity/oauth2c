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
	generateJwkCmd.Flags().StringVar(&jwksConfig.Type, "type", "rsa", "key type (rsa, ps, ec)")
	generateJwkCmd.Flags().IntVar(&jwksConfig.Size, "size", 2048, "key size (rsa)")
	generateJwkCmd.Flags().IntVar(&jwksConfig.Curve, "curve", 256, "curve (ec)")
	generateJwkCmd.Flags().StringVar(&jwksConfig.Use, "use", "sig", "key use (sig, enc)")

	jwksCmd.AddCommand(generateJwkCmd)
}
