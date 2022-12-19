# OAuth2c: user-friendly OAuth CLI

[![status](https://github.com/cloudentity/oauth2c/workflows/build/badge.svg)](https://github.com/cloudentity/oauthc/actions)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![release](https://img.shields.io/github/release-pre/cloudentity/oauth2c.svg)](https://github.com/cloudentity/oauth2c/releases)
[![downloads](https://img.shields.io/github/downloads/cloudentity/oauth2c/total)](https://github.com/cloudentity/oauth2c/releases)

`oauth2c` is a command-line OAuth2 client. Its goal is to make it easy for users to try out different aspects of the OAuth2 protocol and understand how it works. This tool is designed for testing, debugging, and generally interacting with OAuth2 authorization servers. With `oauth2c`, users can easily learn about and experiment with OAuth2 without the need for complex setup or detailed knowledge of the protocol.

![demo](https://user-images.githubusercontent.com/909896/176916616-36d803ef-832a-4bd8-ba8d-f6689e31ed22.gif)

## Features

* A simple and intuitive command-line interface for quickly trying out different OAuth 2.0 grant types and client authentication methods
* Supports all modern OAuth 2.0 grant types: authorization code, implicit, password, client credentials, refresh token, JWT bearer, token exchange
* Supports all client authentication methods: client secret basic, client secret post, client secret JWT, private key JWT, TLS client auth
* Supports the following extensions: PKCE, JARM, PAR

## Installation

To install `oauth2c`, you have several options depending on your operating system.

**Install on Mac**

On Mac, you can install `oauth2c` using `brew` by running the following command:

``` sh
brew install cloudentity/tap/oauth2c
```

**Install on Linux**

On linux, you can install `oauth2c` using the installation script by running the following command:

``` sh
curl -sSfL https://raw.githubusercontent.com/cloudentity/oauth2c/master/install.sh | \
  sudo sh -s -- -b /usr/local/bin latest
```

**Compile from source**

You can also compile `oauth2c` from source using `go`. To do this run the following command:

``` sh
go install github.com/cloudentity/oauth2c@latest
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
      --actor-token string          acting party token
      --actor-token-type string     acting party token type
      --assertion string            claims for jwt bearer assertion
      --auth-method string          token endpoint authentication method
      --client-id string            client identifier
      --client-secret string        client secret
      --encryption-key string       path or url to encryption key in jwks format
      --grant-type string           grant type
  -h, --help                        help for oauthc
      --insecure                    allow insecure connections
      --par                         enable pushed authorization requests (PAR)
      --password string             resource owner password credentials grant flow password
      --pkce                        enable proof key for code exchange (PKCE)
      --refresh-token string        refresh token
      --request-object              pass request parameters as jwt
      --response-mode string        response mode
      --response-types strings      response type
      --scopes strings              requested scopes
      --signing-key string          path or url to signing key in jwks format
  -s, --silent                      silent mode
      --subject-token string        third party token
      --subject-token-type string   third party token type
      --tls-cert string             path to tls cert pem file
      --tls-key string              path to tls key pem file
      --tls-root-ca string          path to tls root ca pem file
      --username string             resource owner password credentials grant flow username
```

You will be asked to provide the necessary information, such as the grant type, client authentication method, and any other relevant details (if not already provided).

`oauth2c` opens a browser for flows such as authorization code and starts an HTTP server which acts as a client application and waits for a callback.

> **Note**: To make browser flows work add `http://localhost:9876/callback` as a redirect URL to your client.

For more information on the available options and arguments for each grant type, run `oauth2c --help`.

## Example

Run the following command to get an access token using authorization code flow:

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```

See [examples](docs/examples.md) for more.

## License

`oauth2c` is released under the [Apache v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Contributing

We welcome contributions! If you have an idea for a new feature or have found a bug, please open an issue on GitHub.
