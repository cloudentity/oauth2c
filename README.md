# oauth2c
User-friendly command-line client for OAuth2

## Installation

``` sh
go install github.com/cloudentity/oauth2c@latest
```

## Flows

### Authorization code

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type authorization_code \
  --auth-method client_secret_basic
```

### Authorization code + PKCE

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --pkce
```

### Client credentials

``` sh
$ oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic
```
