# oauth2c
User-friendly command-line client for OAuth2

## Installation

``` sh
go install github.com/cloudentity/oauth2c@latest
```

## Flows

### Authorization code

``` sh
$ oauth2c https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf \
  --client-id casoe9uvn3otr0gm4rl0 \
  --client-secret XOXtcz8I9ZdCFAAcxtYmYfJ6K1iBqng0CfQ724CG0o0 \
  --grant-type authorization_code \
  --auth-method client_secret_basic
```

### Authorization code + PKCE

``` sh
$ oauth2c https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf \
  --client-id casoe9uvn3otr0gm4rl0 \
  --client-secret XOXtcz8I9ZdCFAAcxtYmYfJ6K1iBqng0CfQ724CG0o0 \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --pkce
```

### Client credentials

``` sh
$ oauth2c https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf \
  --client-id casoe9uvn3otr0gm4rl0 \
  --client-secret XOXtcz8I9ZdCFAAcxtYmYfJ6K1iBqng0CfQ724CG0o0 \
  --grant-type client_credentials \
  --auth-method client_secret_basic
```
