package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/go-jose/go-jose/v3/jwt"
	"strconv"
	"strings"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/grantae/certinfo"
	"github.com/pterm/pterm"
	"github.com/tidwall/pretty"
)

func Logln() {
	if silent {
		return
	}

	pterm.Println()
}

func Logfln(msg string, args ...interface{}) {
	if silent {
		return
	}

	pterm.Printfln(msg, args...)
}

func LogHeader(msg string) {
	if silent {
		return
	}

	pterm.DefaultHeader.WithFullWidth().Println(msg)
}

func LogSection(msg string) {
	if silent {
		return
	}

	pterm.DefaultSection.Println(msg)
}

func LogAction(msg string) func(string) {
	if silent {
		return func(string) {}
	}

	done, _ := pterm.DefaultSpinner.Start(msg)
	return func(s string) {
		done.Success(s)
	}
}

func LogBox(title string, msg string, args ...interface{}) {
	if silent {
		return
	}

	pterm.DefaultBox.WithTitle(title).Printfln(msg, args...)
}

func LogError(err error) {
	pterm.Error.PrintOnError(err)
}

func LogWarning(msg string) {
	if silent {
		return
	}

	pterm.Warning.Println(msg)
}

func LogInputData(cc oauth2.ClientConfig) {
	if silent {
		return
	}

	data := pterm.TableData{
		{"Issuer URL", cc.IssuerURL},
		{"Grant type", cc.GrantType},
		{"Auth method", cc.AuthMethod},
		{"Scopes", strings.Join(cc.Scopes, ", ")},
		{"Response types", strings.Join(cc.ResponseType, ", ")},
		{"Response mode", cc.ResponseMode},
		{"PKCE", strconv.FormatBool(cc.PKCE)},
		{"Client ID", cc.ClientID},
		{"Client secret", cc.ClientSecret},
		{"Username", cc.Username},
		{"Password", cc.Password},
		{"Refresh token", cc.RefreshToken},
		{"Signing key", cc.SigningKey},
		{"Subject token type", cc.SubjectTokenType},
		{"Actors token type", cc.ActorTokenType},
		{"TLS client cert", cc.TLSCert},
		{"TLS client key", cc.TLSKey},
		{"TLS root CA", cc.TLSRootCA},
	}

	nonEmptyData := pterm.TableData{}

	for _, vs := range data {
		if vs[1] != "" {
			nonEmptyData = append(nonEmptyData, vs)
		}
	}

	if err := pterm.DefaultTable.WithData(nonEmptyData).WithBoxed().Render(); err != nil {
		pterm.Error.Println(err)
		return
	}

	pterm.Println()
}

func LogJson(value interface{}) {
	if silent {
		return
	}

	output, err := json.Marshal(value)

	if err != nil {
		pterm.Error.Println(err)
		return
	}

	pterm.Print(string(pretty.Color(pretty.Pretty(output), nil)))
}

func LogRequest(r oauth2.Request) {
	if silent {
		return
	}

	if r.URL == nil {
		return
	}

	if r.URL.Scheme != "" {
		pterm.Println(pterm.FgLightMagenta.Sprint(r.Method) + " " + pterm.FgYellow.Sprintf("%s://%s%s", r.URL.Scheme, r.URL.Host, r.URL.Path))
	} else {
		pterm.Println(pterm.FgLightMagenta.Sprint(r.Method) + " " + pterm.FgYellow.Sprint(r.URL.Path))
	}

	if len(r.Headers) > 0 {
		pterm.Println(pterm.FgGray.Sprint("Headers:"))
	}

	for k, vs := range r.Headers {
		pterm.Println(pterm.FgLightBlue.Sprintf("  %s: ", k) + strings.Join(vs, ", "))
	}

	if len(r.URL.Query()) > 0 {
		pterm.Println(pterm.FgGray.Sprint("Query params:"))
	}

	for k, vs := range r.URL.Query() {
		pterm.Println(pterm.FgLightBlue.Sprintf("  %s: ", k) + strings.Join(vs, ", "))
	}

	if len(r.Form) > 0 {
		pterm.Println(pterm.FgGray.Sprint("Form post:"))
	}

	for k, vs := range r.Form {
		pterm.Println(pterm.FgLightBlue.Sprintf("  %s: ", k) + strings.Join(vs, ", "))
	}

	if r.Cert != nil {
		if info, err := certinfo.CertificateText(r.Cert); err == nil {
			pterm.Println()
			pterm.FgGray.Println(info)
		}
	}
}

func LogRequestln(request oauth2.Request) {
	if silent {
		return
	}

	LogRequest(request)
	pterm.Println()
}

func LogRequestAndResponse(request oauth2.Request, response interface{}) {
	if silent {
		return
	}

	LogRequest(request)
	pterm.Println(pterm.FgGray.Sprint("Response:"))
	LogJson(response)
}

func LogRequestAndResponseln(request oauth2.Request, response interface{}) {
	if silent {
		return
	}

	LogRequestAndResponse(request, response)
	pterm.Println()
}

func LogTokenPayload(response oauth2.TokenResponse) {
	var (
		atClaims map[string]interface{}
		idClaims map[string]interface{}
		err      error
	)

	if silent {
		return
	}

	if response.AccessToken != "" {
		if _, atClaims, err = oauth2.ParseJWT(response.AccessToken); err != nil {
			pterm.Error.Println(err)
		} else {
			pterm.Println(pterm.FgGray.Sprint("Access token:"))
			LogJson(atClaims)
		}
	}

	if response.IDToken != "" {
		if _, idClaims, err = oauth2.ParseJWT(response.IDToken); err != nil {
			pterm.Error.Println(err)
		} else {
			pterm.Println(pterm.FgGray.Sprint("ID token:"))
			LogJson(idClaims)
		}
	}
}

func LogTokenPayloadln(response oauth2.TokenResponse) {
	if silent {
		return
	}

	LogTokenPayload(response)
	pterm.Println()
}

func LogAuthMethod(config oauth2.ClientConfig) {
	if silent {
		return
	}

	switch config.AuthMethod {
	case oauth2.ClientSecretBasicAuthMethod:
		pterm.DefaultBox.WithTitle("Client Secret Basic").Printfln("Authorization = Basic BASE64-ENCODE(ClientID:ClientSecret)")
		pterm.Println()
	}
}

func LogJARM(request oauth2.Request) {
	if silent {
		return
	}

	if len(request.JARM) != 0 {
		pterm.Println(pterm.FgGray.Sprint("JARM:"))
		LogJson(request.JARM)
	}
}

func LogAssertion(request oauth2.Request, title string, name string) {
	var (
		assertion = request.Form.Get(name)
		token     *jwt.JSONWebToken
		claims    map[string]interface{}
		err       error
	)

	if silent {
		return
	}

	if assertion == "" {
		return
	}

	if token, claims, err = oauth2.ParseJWT(assertion); err != nil {
		pterm.Error.Println(err)
		return
	}

	pterm.DefaultBox.WithTitle(title).Printfln("%s = JWT-%s(payload)", name, token.Headers[0].Algorithm)
	pterm.Println()
	pterm.Println("Payload")
	LogJson(claims)
	pterm.Println("")

	pterm.Println("Key")
	switch key := request.Key.(type) {
	case *rsa.PrivateKey:
		p := bytes.Buffer{}

		if err = pem.Encode(&p, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		}); err != nil {
			pterm.Error.Println(err)
		}

		pterm.FgGray.Printfln(p.String())
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(key)

		if err != nil {
			pterm.Error.Println(err)
		}

		p := bytes.Buffer{}

		if err = pem.Encode(&p, &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: b,
		}); err != nil {
			pterm.Error.Println(err)
		}

		pterm.FgGray.Printfln(p.String())
	case []byte:
		pterm.FgGray.Println(string(key))
	}

	pterm.Println()
}

func LogSubjectTokenAndActorToken(request oauth2.Request) {
	var (
		subjectToken       = request.Form.Get("subject_token")
		actorToken         = request.Form.Get("actor_token")
		subjectTokenClaims map[string]interface{}
		actorTokenClaims   map[string]interface{}
		err                error
	)

	if silent {
		return
	}

	if subjectToken != "" {
		if _, subjectTokenClaims, err = oauth2.ParseJWT(subjectToken); err != nil {
			pterm.Error.Println(err)
		} else {
			pterm.Println(pterm.FgGray.Sprint("Subject token:"))
			LogJson(subjectTokenClaims)
		}
	}

	if actorToken != "" {
		if _, actorTokenClaims, err = oauth2.ParseJWT(actorToken); err != nil {
			pterm.Error.Println(err)
		} else {
			pterm.Println(pterm.FgGray.Sprint("Actor token:"))
			LogJson(actorTokenClaims)
		}
	}

	pterm.Println()
}
