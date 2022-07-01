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
  oauthc [issuer url or json config file] [flags]

Flags:
      --auth-method string       token endpoint authentication method
      --client-id string         client identifier
      --client-secret string     client secret
      --grant-type string        grant type
  -h, --help                     help for oauthc
      --no-pkce                  disable proof key for code exchange (PKCE)
      --password string          resource owner password credentials grant flow password
      --pkce                     enable proof key for code exchange (PKCE)
      --refresh-token string     refresh token
      --response-mode string     response mode
      --response-types strings   response type
      --scopes strings           requested scopes
      --username string          resource owner password credentials grant flow username
```

> To make browser flows work add `http://localhost:9876/callback` redirect URL to your client.

## Grant types

### Authorization code

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --no-pkce
```

### Authorization code + PKCE

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --pkce
```

### Implicit

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --response-types token \
  --response-mode form_post \
  --grant-type implicit \
  --scopes openid,email,offline_access
```

### Hybrid

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code,id_token \
  --response-mode form_post \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --no-pkce
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


### Refresh token

> For this flow request refresh token using `offline_access` scope first.

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type refresh_token\
  --auth-method client_secret_basic \
  --refresh-token 1X1IvWR8p5rgKnH2YNmHGd4pZp8Dq-85xzUQuJejT_g.O_DS8Y4eiTS5jZ47_eBv3VbwP4zQUyxjNVW93AyU82k
```

### Resource Owner Password Credentials Flow

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type password --username demo --password demo \
  --auth-method client_secret_basic \
  --scopes openid
```

## Auth methods

### Client Secret Basic

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```

### Client Secret Post

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauosoo2omc4fr8ai1fg \
  --client-secret ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM \
  --grant-type client_credentials \
  --auth-method client_secret_post \
  --scopes introspect_tokens,revoke_tokens
```
