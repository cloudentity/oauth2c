# oauth2c
User-friendly command-line client for OAuth2

[![asciicast](https://asciinema.org/a/5Y95hwfTT8DPPHtgIl9qnsPXA.svg)](https://asciinema.org/a/5Y95hwfTT8DPPHtgIl9qnsPXA)

## Installation

``` sh
go install github.com/cloudentity/oauth2c@latest
```

## Examples

Authorization code

``` sh
[I] ➜ oauth2c https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf \
  --client-id casoe9uvn3otr0gm4rl0 \
  --client-secret XOXtcz8I9ZdCFAAcxtYmYfJ6K1iBqng0CfQ724CG0o0

 ██████   █████  ██    ██ ████████ ██   ██ ██████   ██████
██    ██ ██   ██ ██    ██    ██    ██   ██      ██ ██
██    ██ ███████ ██    ██    ██    ███████  █████  ██
██    ██ ██   ██ ██    ██    ██    ██   ██ ██      ██
 ██████  ██   ██  ██████     ██    ██   ██ ███████  ██████


               Authorization Code Flow


# Request authorization

GET https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf/oauth2/authorize
Query params:
  client_id: casoe9uvn3otr0gm4rl0
  redirect_uri: http://localhost:9876/callback
  response_type: code

Open the following URL:

https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf/oauth2/authorize?client_id=casoe9uvn3otr0gm4rl0&redirect_uri=http%3A%2F%2Flocalhost%3A9876%2Fcallback&response_type=code

Opening in existing browser session.

GET /callback
Query params:
  code: Q42usZjrDDRKr6Wlif-uGushdMc5ZCRCQqoqlQtQAwE.zjhLyQ9qjcHGoQ1oSguopjwioE_gb-caHXvdJG5B_CE
  scope: email openid profile
  state:

 SUCCESS  Obtained authorization code

# Exchange authorization code for token

POST https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf/oauth2/token
Headers:
  Content-Type: application/x-www-form-urlencoded
Form post:
  grant_type: authorization_code
  code: Q42usZjrDDRKr6Wlif-uGushdMc5ZCRCQqoqlQtQAwE.zjhLyQ9qjcHGoQ1oSguopjwioE_gb-caHXvdJG5B_CE
  client_id: casoe9uvn3otr0gm4rl0
  client_secret: XOXtcz8I9ZdCFAAcxtYmYfJ6K1iBqng0CfQ724CG0o0
  redirect_uri: http://localhost:9876/callback
Response:
{
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc0MjE5NDcxNDA3NjE1ODkzOTAwMDI4NDgwNzAyNjAzMjE1NDIyIiwidHlwIjoiSldUIn0.eyJhY3IiOiIxIiwiYWlkIjoic2RhZnNkZnNmIiwiYW1yIjpbInB3ZCJdLCJhdWQiOlsiY2Fzb2U5dXZuM290cjBnbTRybDAiLCJzcGlmZmU6Ly9tYmRlc2lnbi5ldS5hdXRoei5jbG91ZGVudGl0eS5pby9tYmRlc2lnbi9zZGFmc2Rmc2Yvc2RhZnNkZnNmLXByb2ZpbGUiXSwiZHVwYTIiOiJxd2UiLCJleHAiOjE2NTY0Mzc0ODgsImlhdCI6MTY1NjQzMzg4OCwiaWRwIjoiYzhibGJoNDlmaW50MWtrcDB1dGciLCJpc3MiOiJodHRwczovL21iZGVzaWduLmV1LmF1dGh6LmNsb3VkZW50aXR5LmlvL21iZGVzaWduL3NkYWZzZGZzZiIsImp0aSI6IjViODM5YWNlLTYwZWQtNDBiZC05MmI0LWU1M2ZiZTJhMTMyMSIsIm5iZiI6MTY1NjQzMzg4OCwic2NwIjpbImVtYWlsIiwib3BlbmlkIiwicHJvZmlsZSJdLCJzdCI6InBhaXJ3aXNlIiwic3ViIjoiNDA4NzhhNmZiMDA4YmE2YzdlOGY1OGZhNzllNmUxOWQxZGI4Zjg2ZTY1YzNjZGI0NGIwYjI2NjdhMzMwNzBjMyIsInRpZCI6Im1iZGVzaWduIn0.XTO9nQ75e_6cxYe8A_g0atZoyl7Dmd824jcEZqUjxa90jRTqXtrgdg4rRH1cxeQ5bsoFzfMon3ZNp95kfT02Zg",
  "expires_in": 3599,
  "id_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ijc0MjE5NDcxNDA3NjE1ODkzOTAwMDI4NDgwNzAyNjAzMjE1NDIyIiwidHlwIjoiSldUIn0.eyJhY3IiOiIxIiwiYW1yIjpbInB3ZCJdLCJhdWQiOiJjYXNvZTl1dm4zb3RyMGdtNHJsMCIsImF1dGhfdGltZSI6MTY1NjQzMzg4NiwiZHVwYSI6Im1hdGV1c3ouYmlsc2tpQGdtYWlsLmNvbSIsImR1cGEzIjoicXdlIiwiZW1haWwiOiJtYXRldXN6LmJpbHNraUBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNjU2NDM3NDg4LCJpYXQiOjE2NTY0MzM4ODgsImlkcCI6ImM4YmxiaDQ5ZmludDFra3AwdXRnIiwiaWRwbSI6InN0YXRpYyIsImlzcyI6Imh0dHBzOi8vbWJkZXNpZ24uZXUuYXV0aHouY2xvdWRlbnRpdHkuaW8vbWJkZXNpZ24vc2RhZnNkZnNmIiwianRpIjoiNWQzN2FmZTItNjhiMC00NGE3LWFhMzUtMTBmOGVjNTdjZjQzIiwibmFtZSI6InF3ZSIsInJhdCI6MTY1NjQzMzg4OCwic3ViIjoiNDA4NzhhNmZiMDA4YmE2YzdlOGY1OGZhNzllNmUxOWQxZGI4Zjg2ZTY1YzNjZGI0NGIwYjI2NjdhMzMwNzBjMyJ9.XS47TLHfHEhqVRxC8Q21nigLVB-LnQOHyHm3kvvPLxNm5wgJ9kLwq3J01J7Wjfxgtx0k_KvEMMTj5p9JJsCwUQ",
  "scope": "email openid profile",
  "token_type": "bearer"
}
Access token:
{
  "acr": "1",
  "aid": "sdafsdfsf",
  "amr": ["pwd"],
  "aud": [
    "casoe9uvn3otr0gm4rl0",
    "spiffe://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf/sdafsdfsf-profile"
  ],
  "dupa2": "qwe",
  "exp": 1656437488,
  "iat": 1656433888,
  "idp": "c8blbh49fint1kkp0utg",
  "iss": "https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf",
  "jti": "5b839ace-60ed-40bd-92b4-e53fbe2a1321",
  "nbf": 1656433888,
  "scp": ["email", "openid", "profile"],
  "st": "pairwise",
  "sub": "40878a6fb008ba6c7e8f58fa79e6e19d1db8f86e65c3cdb44b0b2667a33070c3",
  "tid": "mbdesign"
}
ID token:
{
  "acr": "1",
  "amr": ["pwd"],
  "aud": "casoe9uvn3otr0gm4rl0",
  "auth_time": 1656433886,
  "dupa": "mateusz.bilski@gmail.com",
  "dupa3": "qwe",
  "email": "mateusz.bilski@gmail.com",
  "email_verified": true,
  "exp": 1656437488,
  "iat": 1656433888,
  "idp": "c8blbh49fint1kkp0utg",
  "idpm": "static",
  "iss": "https://mbdesign.eu.authz.cloudentity.io/mbdesign/sdafsdfsf",
  "jti": "5d37afe2-68b0-44a7-aa35-10f8ec57cf43",
  "name": "qwe",
  "rat": 1656433888,
  "sub": "40878a6fb008ba6c7e8f58fa79e6e19d1db8f86e65c3cdb44b0b2667a33070c3"
}

 SUCCESS  Exchanged authorization code for access token
```
