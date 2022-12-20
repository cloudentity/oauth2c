# OAuth2c: user-friendly OAuth CLI

[![status](https://github.com/cloudentity/oauth2c/workflows/build/badge.svg)](https://github.com/cloudentity/oauthc/actions)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![release](https://img.shields.io/github/release-pre/cloudentity/oauth2c.svg)](https://github.com/cloudentity/oauth2c/releases)
[![downloads](https://img.shields.io/github/downloads/cloudentity/oauth2c/total)](https://github.com/cloudentity/oauth2c/releases)

`oauth2c` is a command-line tool for interacting with OAuth 2.0 authorization servers. Its goal is to make it easy to fetch access tokens
using any grant type or client authentication method. It is compliant with almost all basic and advanced OAuth 2.0, OIDC, OIDF FAPI and JWT profiles.

![demo](https://user-images.githubusercontent.com/909896/176916616-36d803ef-832a-4bd8-ba8d-f6689e31ed22.gif)

## Features

* support for **authorization code**, **hybrid**, **implicit**, **password**, **client credentials**, **refresh token**, **JWT bearer**, **token exchange**, **device** grant flows
* support for **client secret basic**, **client secret post**, **client secret JWT**, **private key JWT**, **TLS client auth** client authentication methods
* passing request parameters as plaintext, signed, and/or encrypted JWT
* support for **Proof Key for Code Exchange** (**PKCE**)
* support for **JWT Secured Authorization Response Mode** (**JARM**)
* support for **Pushed Authorization Requests** (**PAR**)

## Installation

To install `oauth2c`, you have several options depending on your operating system.

### Install on Mac

On Mac, you can install `oauth2c` using `brew` by running the following command:

``` sh
brew install cloudentity/tap/oauth2c
```

### Install on Linux

On linux, you can install `oauth2c` using the installation script by running the following command:

``` sh
curl -sSfL https://raw.githubusercontent.com/cloudentity/oauth2c/master/install.sh | \
  sudo sh -s -- -b /usr/local/bin latest
```

### Compile from source

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

The issuer URL is base URL where `oauth2c` can find the `/.well-known/openid-configuration` endpoint.

The available flags are:

### Core

| Flag               | Description |
|--------------------|-------------|
| `--grant-type`     |             |
| `--auth-method`    |             |
| `--client-id`      |             |
| `--client-secret`  |             |
| `--scopes`         |             |
| `--response-mode`  |             |
| `--response-types` |             |
| `--signing-key`    |             |
| `--encryption-key` |             |
| `--tls-cert`       |             |
| `--tls-key`        |             |
| `--tls-root-ca`    |             |
| `--insecure`       |             |
| `--silent`         |             |
| `--help`           |             |

### Grant flows

#### Refresh token

#### Password grant

#### JWT Bearer grant

#### Token exchange

### Extensions

``` sh
      --request-object              pass request parameters as jwt
      --par                         enable pushed authorization requests (PAR)
      --pkce                        enable proof key for code exchange (PKCE)
      --refresh-token string        refresh token
      --username string             resource owner password credentials grant flow username
      --password string             resource owner password credentials grant flow password
      --assertion string            claims for jwt bearer assertion
      --subject-token string        third party token
      --subject-token-type string   third party token type
      --actor-token string          acting party token
      --actor-token-type string     acting party token type
```

`oauth2c` opens a browser for flows such as authorization code and starts an HTTP server which acts as a client application and waits for a callback.

> **Note**: To make browser flows work add `http://localhost:9876/callback` as a redirect URL to your client.

`oauth2c` prints all the requests it made to obtain an access token. If you want to integrate it with CI/CD pipeline use the `--silent` flag.

For more information on the available options and arguments run `oauth2c --help`.

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
