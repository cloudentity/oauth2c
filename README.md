# oauth2c

[![status](https://github.com/cloudentity/oauth2c/workflows/build/badge.svg)](https://github.com/cloudentity/oauthc/actions)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![release](https://img.shields.io/github/release-pre/cloudentity/oauth2c.svg)](https://github.com/cloudentity/oauth2c/releases)
[![downloads](https://img.shields.io/github/downloads/cloudentity/oauth2c/total)](https://github.com/cloudentity/oauth2c/releases)

`oauth2c` is a command-line tool that simplifies the process of experimenting with different grant types and client authentication methods for OAuth 2.0.

![demo](https://user-images.githubusercontent.com/909896/176916616-36d803ef-832a-4bd8-ba8d-f6689e31ed22.gif)

## Features

* Simple and intuitive interface for quickly experimenting with different OAuth 2.0 grant types and client authentication methods
* Supports all modern OAuth 2.0 grant types: authorization code, implicit, password, client credentials, refresh token, JWT bearer
* Supports all client authentication methods: client secret basic, client secret post, client secret JWT, private key JWT, TLS client auth

## Installation

To install `oauth2c`, simply run the following command:

``` sh
curl -sSfL https://raw.githubusercontent.com/cloudentity/oauth2c/master/install.sh | \
  sudo sh -s -- -b /usr/local/bin latest
```

Alternatively, you can download a pre-built binary from the [releases page].

[releases page]: https://github.com/cloudentity/oauth2c/releases

## Usage

To use `oauth2c`, run the following command and follow the prompts:

``` sh
oauth2c [issuer url] [flags]
```

The available flags are:

``` sh
      --assertion string         claims for jwt bearer assertion (standard claims such as iss, aud, iat, exp, jti are automatically generated)
      --auth-method string       token endpoint authentication method
      --client-id string         client identifier
      --client-secret string     client secret
      --grant-type string        grant type
      --insecure                 allow insecure connections
      --no-pkce                  disable proof key for code exchange (PKCE)
      --password string          resource owner password credentials grant flow password
      --pkce                     enable proof key for code exchange (PKCE)
      --refresh-token string     refresh token
      --response-mode string     response mode
      --response-types strings   response type
      --scopes strings           requested scopes
      --signing-key string       path or url to signing key in jwks format
      --tls-cert string          path to tls cert pem file
      --tls-key string           path to tls key pem file
      --tls-root-ca string       path to tls root ca pem file
      --username string          resource owner password credentials grant flow username
```

You will be asked to provide the necessary information, such as the grant type, client authentication method, and any other relevant details (if not already provided).

Once authenticated, you will be able to use the access token to access the OAuth2 provider's API.

> **Note**: To make browser flows work add `http://localhost:9876/callback` as a redirect URL to your client.

For more information on the available options and arguments for each grant type, run `oauth2c --help`.

## Examples

Here are a few examples of using oauth2c with different grant types and client authentication methods:

### Grant types

#### Authorization code

This grant type involves a two-step process where the user first grants permission to access their data, and
then the client exchanges the authorization code for an access token. This grant type is typically used
in server-side applications.

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

[Learn more about authorization code flow](https://cloudentity.com/developers/basics/oauth-grant-types/authorization-code-flow/)

#### Authorization code + PKCE

The Proof Key for Code Exchange (PKCE) is an extension to the OAuth2 authorization code grant flow that
provides additional security when authenticating with an OAuth2 provider. In the PKCE flow, the client
generates a code verifier and a code challenge, which are then sent to the OAuth2 provider during
the authorization request. The provider returns an authorization code, which the client then exchanges for
an access token along with the code verifier. The provider verifies the code verifier to ensure that the
request is coming from the same client that initiated the authorization request.

This additional step helps to prevent attackers from intercepting the authorization code and using it to
obtain an access token. PKCE is recommended for all public clients, such as single-page or mobile
applications, where the client secret cannot be securely stored. oauth2c supports PKCE as an optional
parameter when using the authorization code grant type.

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

[Learn more about authorization code flow with pkce](https://cloudentity.com/developers/basics/oauth-grant-types/authorization-code-with-pkce/)

#### Implicit

This grant type is similar to the authorization code grant, but the access token is returned directly to
the client without an intermediate authorization code. This grant type is typically used in single-page or
mobile applications.

> **Note**: The implicit flow is not recommended for use in modern OAuth2 applications. It does not provide a secure method for obtaining new access tokens. Instead, it is recommended to use the authorization code flow with PKCE (Proof Key for Code Exchange) for added security.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --response-types token \
  --response-mode form_post \
  --grant-type implicit \
  --scopes openid,email,offline_access
```

[Learn more about implicit flow](https://cloudentity.com/developers/basics/oauth-grant-types/implicit-flow/)

#### Hybrid

To use the OAuth2 hybrid flow to obtain an authorization code and an ID token, the client first sends an authorization request to the OAuth2 provider. The request should include the code and id_token response types.

The OAuth2 provider will then return an authorization code and an ID token to the client, either in the response body or as fragment parameters in the redirect URL, depending on the response mode specified in the request. The client can then use the authorization code to obtain an access token by sending a token request to the OAuth2 provider.

The ID token can be used to verify the identity of the authenticated user, as it contains information such as the user's name and email address. The ID token is typically signed by the OAuth2 provider, so the client can verify its authenticity using the provider's public key.

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

[Learn more about the hybrid flow](https://cloudentity.com/developers/basics/oauth-grant-types/hybrid-flow/)

#### Client credentials

This grant type involves the client providing its own credentials (i.e. client ID and client secret) to
the OAuth2 server, which then returns an access token. This grant type is typically used for
server-to-server communication, where the client is a trusted server rather than a user.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about the client credentials flow](https://cloudentity.com/developers/basics/oauth-grant-types/client-credentials-flow/)

#### Refresh token

This grant type involves the client providing a refresh token to the OAuth2 server, which then returns
a new access token. This grant type is used to obtain new access tokens when the original access
token has expired.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type refresh_token\
  --auth-method client_secret_basic \
  --refresh-token 1X1IvWR8p5rgKnH2YNmHGd4pZp8Dq-85xzUQuJejT_g.O_DS8Y4eiTS5jZ47_eBv3VbwP4zQUyxjNVW93AyU82k
```

[Learn more about the refresh token flow](https://cloudentity.com/developers/basics/oauth-grant-types/refresh-token-flow/)

#### Password

This grant type involves the client providing the user's username and password to the OAuth2 server, which
then returns an access token. This grant type should only be used in secure environments, as it involves
sending the user's credentials to the OAuth2 server.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type password --username demo --password demo \
  --auth-method client_secret_basic \
  --scopes openid
```

[Learn more about the password flow](https://cloudentity.com/developers/basics/oauth-grant-types/resource-owner-password-credentials/)

#### JWT Bearer

This grant type involves the client providing a JSON Web Token (JWT) to the OAuth2 server, which then returns
an access token. This grant type is typically used when the client is a trusted third-party, such as a JWT
issuer.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:jwt-bearer \
  --auth-method client_secret_basic \
  --scopes email \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.json \
  --assertion '{"sub":"jdoe@example.com"}'
```

[Learn more about the jwt bearer flow](https://cloudentity.com/developers/basics/oauth-grant-types/using-jwt-profile-for-authorization-flows/)

### Auth methods

#### Client Secret Basic

This client authentication method involves the client sending its client ID and client secret as part of the
HTTP Basic authentication header in the request to the OAuth2 server. This method is simple and widely
supported, but it is less secure than other methods because the client secret is sent in the clear.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about client secret basic](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_basic)

#### Client Secret Post

This client authentication method involves the client sending its client ID and client secret as part of
the request body in the request to the OAuth2 server. This method provides more security than the
basic authentication method, but it requires the request to be sent via HTTPS to prevent the client secret
from being intercepted.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauosoo2omc4fr8ai1fg \
  --client-secret ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM \
  --grant-type client_credentials \
  --auth-method client_secret_post \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about client secret post](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_post)

#### Client Secret JWT

This client authentication method involves the client signing a JSON Web Token (JWT) using its client secret,
and then sending the JWT to the OAuth2 server. This method provides a higher level of security than the
basic or post methods, as the client secret is never sent in the clear.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id ab966ce4f2ac4f4aa641582b099c32d3 \
  --client-secret 578-WfFYfBheWb8gJpHYXMRRqR5HN0qv7d7xIolJnIE \
  --grant-type client_credentials \
  --auth-method client_secret_jwt \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about client secret jwt](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_jwt)

#### Private Key JWT

This client authentication method involves the client signing a JSON Web Token (JWT) using its private key,
and then sending the JWT to the OAuth2 server. This method provides a higher level of security than the
JWT methods using a client secret, as the private key is never shared with the OAuth2 server.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id 582af0afb0d74554aa7af47849edb222 \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.json \
  --grant-type client_credentials \
  --auth-method private_key_jwt \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about private key jwt](https://cloudentity.com/developers/basics/oauth-client-authentication/private-key-jwt-client-authentication/)

#### TLS Client Auth

This client authentication method involves the client providing its own certificate as part of the TLS
handshake when connecting to the OAuth2 server. This method provides a high level of security, as the
client's identity is verified using a trusted certificate authority. However, it requires the OAuth2
server to support TLS client authentication, which may not be supported by all OAuth2 providers.

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id 3f07a8c2adea4c1ab353f3ca8e16b8fd \
  --tls-cert https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/cert.pem \
  --tls-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.pem \
  --grant-type client_credentials \
  --auth-method tls_client_auth \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about tls client auth](https://cloudentity.com/developers/basics/oauth-client-authentication/oauth-mtls-client-authentication/)

## License

`oauth2c` is released under the [Apache v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Contributing

We welcome contributions! If you have an idea for a new feature or have found a bug, please open an issue on GitHub.
