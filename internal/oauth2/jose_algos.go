package oauth2

import jose "github.com/go-jose/go-jose/v4"

// JOSE v4 requires explicit algorithm allowlists for Parse* calls.
// As an OAuth2 testing tool we accept every standard JWS/JWE algorithm
// so users can debug servers regardless of their configuration.

var JOSESignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.HS256, jose.HS384, jose.HS512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

var JOSEKeyAlgorithms = []jose.KeyAlgorithm{
	jose.RSA1_5, jose.RSA_OAEP, jose.RSA_OAEP_256,
	jose.A128KW, jose.A192KW, jose.A256KW,
	jose.DIRECT,
	jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
	jose.A128GCMKW, jose.A192GCMKW, jose.A256GCMKW,
	jose.PBES2_HS256_A128KW, jose.PBES2_HS384_A192KW, jose.PBES2_HS512_A256KW,
}

var JOSEContentEncryption = []jose.ContentEncryption{
	jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512,
	jose.A128GCM, jose.A192GCM, jose.A256GCM,
}
