# oauth2c
User-friendly command-line client for OAuth2

## Installation

``` sh
go install github.com/cloudentity/oauth2c@latest
```

## Usage

``` sh
$ oauth2c -h
User-friendly command-line for OAuth2

Usage:
  oauthc [issuer-url] [flags]

Flags:
      --auth-method string     token endpoint authentication method
      --client-id string       client identifier
      --client-secret string   client secret
      --grant-type string      grant type
  -h, --help                   help for oauthc
      --pkce                   enable proof key for code exchange (PKCE)
      --scopes strings         requested scopes
```

## Flows

### Authorization code

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email
```

### Authorization code + PKCE

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email \
  --pkce
```

### Client credentials

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```
