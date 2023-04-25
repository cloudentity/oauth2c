# Examples

Here are a few examples of using oauth2c with different grant types and client authentication methods:

## Grant types

> **NOTE**: The authorization code, implicit, hybrid and device grant flows require browser and user authentication.

### Authorization code

This grant type involves a two-step process where the user first grants permission to access their data, and
then the client exchanges the authorization code for an access token. This grant type is typically used
in server-side applications.

<details>
<summary>Show example</summary>

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
</details>

[Learn more about authorization code flow](https://cloudentity.com/developers/basics/oauth-grant-types/authorization-code-flow/)

### Implicit

This grant type is similar to the authorization code grant, but the access token is returned directly to
the client without an intermediate authorization code. This grant type is typically used in single-page or
mobile applications.

> **Note**: The implicit flow is not recommended for use in modern OAuth2 applications.
> Instead, it is recommended to use the authorization code flow with PKCE (Proof Key for Code Exchange) for added security.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --response-types token \
  --response-mode form_post \
  --grant-type implicit \
  --scopes openid,email,offline_access
```
</details>

[Learn more about implicit flow](https://cloudentity.com/developers/basics/oauth-grant-types/implicit-flow/)

### Hybrid

To use the OAuth2 hybrid flow to obtain an authorization code and an ID token, the client first sends an authorization request to the OAuth2 provider. The request should include the code and id_token response types.

The OAuth2 provider will then return an authorization code and an ID token to the client, either in the response body or as fragment parameters in the redirect URL, depending on the response mode specified in the request. The client can then use the authorization code to obtain an access token by sending a token request to the OAuth2 provider.

The ID token can be used to verify the identity of the authenticated user, as it contains information such as the user's name and email address. The ID token is typically signed by the OAuth2 provider, so the client can verify its authenticity using the provider's public key.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code,id_token \
  --response-mode form_post \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```
</details>

[Learn more about the hybrid flow](https://cloudentity.com/developers/basics/oauth-grant-types/hybrid-flow/)

### Client credentials

This grant type involves the client providing its own credentials to
the OAuth2 server, which then returns an access token. This grant type is typically used for
server-to-server communication, where the client is a trusted server rather than a user.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```
</details>

[Learn more about the client credentials flow](https://cloudentity.com/developers/basics/oauth-grant-types/client-credentials-flow/)

### Refresh token

This grant type involves the client providing a refresh token to the OAuth2 server, which then returns
a new access token.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type refresh_token\
  --auth-method client_secret_basic \
  --refresh-token $REFRESH_TOKEN
```
</details>

> **Note** In order to use this command, you must first set the REFRESH_TOKEN environment variable
>
> <details>
> <summary>Show example</summary>
>
> ``` sh
> export REFRESH_TOKEN=`oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
>   --client-id cauktionbud6q8ftlqq0 \
>   --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
>   --response-types code \
>   --response-mode query \
>   --grant-type authorization_code \
>   --auth-method client_secret_basic \
>   --scopes openid,email,offline_access \
>   --silent | jq -r .refresh_token`
> ```
> </details>

[Learn more about the refresh token flow](https://cloudentity.com/developers/basics/oauth-grant-types/refresh-token-flow/)

### Password

This grant type involves the client providing the user's username and password to the OAuth2 server, which
then returns an access token. This grant type should only be used in secure environments, as it involves
sending the user's credentials to the OAuth2 server.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type password \
  --username demo \
  --password demo \
  --auth-method client_secret_basic \
  --scopes openid
```
</details>

[Learn more about the password flow](https://cloudentity.com/developers/basics/oauth-grant-types/resource-owner-password-credentials/)

### Device

This grant type is a two-step process that allows a user to grant access to their data without
having to enter a username and password. In the first step, the user grants permission for the client to access
their data. In the second step, the client exchanges the authorization code received in the first step for an
access token. This grant type is commonly used in server-side applications, such as when accessing a device
from a TV or other non-interactive device.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:device_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```
</details>

[Learn more about the device flow](https://cloudentity.com/developers/basics/oauth-grant-types/device/)

### JWT Bearer

This grant type involves the client providing a JSON Web Token (JWT) to the OAuth2 server, which then returns
an access token. This grant type is typically used when the client is a trusted third-party, such as a JWT
issuer.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:jwt-bearer \
  --auth-method client_secret_basic \
  --scopes email \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/rsa/key.json \
  --assertion '{"sub":"jdoe@example.com"}'
```
</details>

[Learn more about the jwt bearer flow](https://cloudentity.com/developers/basics/oauth-grant-types/using-jwt-profile-for-authorization-flows/)

### Token exchange

The token exchange OAuth2 grant flow involves the client providing an access token to the OAuth2 server,
which then returns a new access token. This grant type is typically used when the client and the OAuth2
server have a pre-existing trust relationship, such as when the client is a trusted third-party.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:token-exchange \
  --auth-method client_secret_basic \
  --scopes email \
  --subject-token $SUBJECT_TOKEN \
  --subject-token-type urn:ietf:params:oauth:token-type:access_token \
  --actor-token $ACTOR_TOKEN \
  --actor-token-type urn:ietf:params:oauth:token-type:access_token
```
</details>

> **Note** In order to use this command, you must first set the SUBJECT_TOKEN and ACTOR_TOKEN environment variables
>
> <details>
> <summary>Show example</summary>
>
> ``` sh
> export SUBJECT_TOKEN=`oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
>   --client-id cauktionbud6q8ftlqq0 \
>   --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
>   --response-types code \
>   --response-mode query \
>   --grant-type authorization_code \
>   --auth-method client_secret_basic \
>   --scopes openid,email,offline_access \
>   --silent | jq -r .access_token`
> ```
>
> ``` sh
> export ACTOR_TOKEN=`oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
>   --client-id cauktionbud6q8ftlqq0 \
>   --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
>   --grant-type client_credentials \
>   --auth-method client_secret_basic \
>   --scopes introspect_tokens,revoke_tokens \
>   --silent | jq -r .access_token`
> ```
> </details>

[Learn more about the token exchange flow](https://cloudentity.com/developers/basics/oauth-grant-types/token-exchange/)

## Auth methods

### Client Secret Basic

This client authentication method involves the client sending its credentials as part of the
HTTP Basic authentication header in the request to the OAuth2 server. This method is simple and widely
supported, but it is less secure than other methods because the client secret is sent in the clear.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```
</details>

[Learn more about client secret basic](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_basic)

### Client Secret Post

This client authentication method involves the client sending its credentials as part of
the request body in the request to the OAuth2 server. This method provides more security than the
basic authentication method, but it requires the request to be sent via HTTPS to prevent the client secret
from being intercepted.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauosoo2omc4fr8ai1fg \
  --client-secret ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM \
  --grant-type client_credentials \
  --auth-method client_secret_post \
  --scopes introspect_tokens,revoke_tokens
```
</details>

[Learn more about client secret post](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_post)

### Client Secret JWT

This client authentication method involves the client signing a JSON Web Token (JWT) using its client secret,
and then sending the JWT to the OAuth2 server. This method provides a higher level of security than the
basic or post methods, as the client secret is never sent in the clear.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id ab966ce4f2ac4f4aa641582b099c32d3 \
  --client-secret 578-WfFYfBheWb8gJpHYXMRRqR5HN0qv7d7xIolJnIE \
  --grant-type client_credentials \
  --auth-method client_secret_jwt \
  --scopes introspect_tokens,revoke_tokens
```
</details>

[Learn more about client secret jwt](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_jwt)

### Private Key JWT

This client authentication method involves the client signing a JSON Web Token (JWT) using its private key,
and then sending the JWT to the OAuth2 server. This method provides a higher level of security than the
JWT methods using a client secret, as the private key is never shared with the OAuth2 server.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id 582af0afb0d74554aa7af47849edb222 \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/rsa/key.json \
  --grant-type client_credentials \
  --auth-method private_key_jwt \
  --scopes introspect_tokens,revoke_tokens
```
</details>

[Learn more about private key jwt](https://cloudentity.com/developers/basics/oauth-client-authentication/private-key-jwt-client-authentication/)

### TLS Client Auth

This client authentication method involves the client providing its own certificate as part of the TLS
handshake when connecting to the OAuth2 server. This method provides a high level of security, as the
client's identity is verified using a trusted certificate authority. However, it requires the OAuth2
server to support TLS client authentication, which may not be supported by all OAuth2 providers.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id 3f07a8c2adea4c1ab353f3ca8e16b8fd \
  --tls-cert https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/cert.pem \
  --tls-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.pem \
  --grant-type client_credentials \
  --auth-method tls_client_auth \
  --scopes introspect_tokens,revoke_tokens
```
</details>

[Learn more about tls client auth](https://cloudentity.com/developers/basics/oauth-client-authentication/oauth-mtls-client-authentication/)

### None with PKCE

Public clients, such as mobile apps, are unable to authenticate themselves to the authorization server in the same way that confidential clients can because they do not have a client secret. To protect themselves from having their authorization codes intercepted and used by attackers, public clients can use PKCE (Proof Key for Code Exchange) during the authorization process. PKCE provides an additional layer of security by ensuring that the authorization code can only be exchanged for a token by the same client that initially requested it. This helps prevent unauthorized access to the token.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id db5e375e7b634095b24bbb683fcb955b \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method none \
  --scopes openid,email \
  --pkce
```
</details>

[Lean more about none with PKCE](https://cloudentity.com/developers/basics/oauth-client-authentication/client-auth-set-to-none-with-pkce/)

## Extensions

### Request Object

The Request Object is a JWT that contains the parameters of an authorization request. It allows the request to be passed along as a single,
self-contained parameter, and it can be optionally signed and/or encrypted for added security.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --request-object
```

</details>

### PKCE

The Proof Key for Code Exchange (PKCE) is an extension to the OAuth2 authorization code grant flow that
provides additional security when authenticating with an OAuth2 provider. In the PKCE flow, the client
generates a code verifier and a code challenge, which are then sent to the OAuth2 provider during
the authorization request. The provider returns an authorization code, which the client then exchanges for
an access token along with the code verifier. The provider verifies the code verifier to ensure that the
request is coming from the same client that initiated the authorization request.

This additional step helps to prevent attackers from intercepting the authorization code and using it to
obtain an access token. PKCE is recommended for all public clients, such as single-page or mobile
applications, where the client secret cannot be securely stored.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id db5e375e7b634095b24bbb683fcb955b \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method none \
  --scopes openid,email \
  --pkce
```
</details>

[Learn more about authorization code flow with pkce](https://cloudentity.com/developers/basics/oauth-grant-types/authorization-code-with-pkce/)

### JARM

JWT-secured OAuth 2.0 authorization response, also known as JARM, is a method of securely transmitting authorization
information in an OAuth 2.0 authorization response using JSON Web Tokens (JWT). This allows the authorization response
to be verified by the client, ensuring that the information is coming from a trusted source and has not been tampered
with. The JWT is signed using a secret key shared between the authorization server and the client, allowing the client
to verify the authenticity of the JWT. This provides an additional layer of security to the OAuth 2.0 authorization process.

**Signed JWT**

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query.jwt \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```
</details>

**Signed and encrypted JWT**

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauosoo2omc4fr8ai1fg \
  --client-secret ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM \
  --response-types code \
  --response-mode query.jwt \
  --grant-type authorization_code \
  --auth-method client_secret_post \
  --scopes openid,email,offline_access \
  --encryption-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/rsa/key.json
```
</details>

### PAR

Pushed Authorization Requests (PAR) is an extension of the OAuth 2.0 specification that enables client applications
to push the payloads of authorization requests directly to the authorization server via a PAR endpoint.
This allows for more efficient and secure handling of authorization requests. PAR can be useful for client applications
that require a high level of security, and may be required for compliance with certain security profiles and regulations.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --par
```
</details>

[Learn more about PAR](https://cloudentity.com/developers/basics/oauth-grant-types/pushed-authorization-requests/)

### DPoP

DPoP, or Demonstration of Proof of Possession, is an extension that describes a technique to cryptographically bind access
tokens to a particular client when they are issued. This is one of many attempts at improving the security of Bearer Tokens
by requiring the application using the token to authenticate itself.

<details>
<summary>Show example</summary>

``` sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/ps/key.json \
  --dpop
```
</details>
