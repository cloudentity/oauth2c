# oauth2c

[![status](https://github.com/cloudentity/oauth2c/workflows/build/badge.svg)](https://github.com/cloudentity/oauthc/actions)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![release](https://img.shields.io/github/release-pre/cloudentity/oauth2c.svg)](https://github.com/cloudentity/oauth2c/releases)

User-friendly command-line client for OAuth2

![demo](https://user-images.githubusercontent.com/909896/176916616-36d803ef-832a-4bd8-ba8d-f6689e31ed22.gif)


## Installation

``` sh
curl -sSfL https://raw.githubusercontent.com/cloudentity/oauth2c/master/install.sh | \
  sudo sh -s -- -b /usr/local/bin latest
```

Binaries are also available on the [releases page].

[releases page]: https://github.com/cloudentity/oauth2c/releases

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
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
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
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
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
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --response-types token \
  --response-mode form_post \
  --grant-type implicit \
  --scopes openid,email,offline_access
```

### Hybrid

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
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
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```


### Refresh token

> For this flow request refresh token using `offline_access` scope first.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type refresh_token\
  --auth-method client_secret_basic \
  --refresh-token 1X1IvWR8p5rgKnH2YNmHGd4pZp8Dq-85xzUQuJejT_g.O_DS8Y4eiTS5jZ47_eBv3VbwP4zQUyxjNVW93AyU82k
```

### Resource Owner Password Credentials Flow

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type password --username demo --password demo \
  --auth-method client_secret_basic \
  --scopes openid
```

### JWT Bearer

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:jwt-bearer \
  --auth-method client_secret_basic \
  --scopes email \
  --signing-key https://pastebin.com/raw/WMkzhjhm \
  --assertion '{"sub":"jdoe@example.com"}'
```

## Auth methods

### Client Secret Basic

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```

### Client Secret Post

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauosoo2omc4fr8ai1fg \
  --client-secret ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM \
  --grant-type client_credentials \
  --auth-method client_secret_post \
  --scopes introspect_tokens,revoke_tokens
```

### Client Secret JWT

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id ab966ce4f2ac4f4aa641582b099c32d3 \
  --client-secret 578-WfFYfBheWb8gJpHYXMRRqR5HN0qv7d7xIolJnIE \
  --grant-type client_credentials \
  --auth-method client_secret_jwt \
  --scopes introspect_tokens,revoke_tokens
```
