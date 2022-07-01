package cmd

import (
	"encoding/json"
	"strings"

	"github.com/cloudentity/oauth2c/internal/oauth2"
	"github.com/golang-jwt/jwt"
	"github.com/pterm/pterm"
	"github.com/tidwall/pretty"
)

func LogJson(value interface{}) {
	output, err := json.Marshal(value)

	if err != nil {
		pterm.Error.Println(err)
		return
	}

	pterm.Print(string(pretty.Color(pretty.Pretty(output), nil)))
}

func LogRequest(r oauth2.Request) {
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
}

func LogRequestln(request oauth2.Request) {
	LogRequest(request)
	pterm.Println()
}

func LogRequestAndResponse(request oauth2.Request, response interface{}) {
	LogRequest(request)
	pterm.Println(pterm.FgGray.Sprint("Response:"))
	LogJson(response)
}

func LogRequestAndResponseln(request oauth2.Request, response interface{}) {
	LogRequestAndResponse(request, response)
	pterm.Println()
}

func LogTokenPayload(response oauth2.TokenResponse) {
	var (
		atClaims jwt.MapClaims
		idClaims jwt.MapClaims
	)

	if response.AccessToken != "" {
		if _, _, err := parser.ParseUnverified(response.AccessToken, &atClaims); err != nil {
			pterm.Error.Println(err)
		} else {
			pterm.Println(pterm.FgGray.Sprint("Access token:"))
			LogJson(atClaims)
		}
	}

	if response.IDToken != "" {
		if _, _, err := parser.ParseUnverified(response.IDToken, &idClaims); err != nil {
			pterm.Error.Println(err)
		} else {
			pterm.Println(pterm.FgGray.Sprint("ID token:"))
			LogJson(idClaims)
		}
	}
}

func LogTokenPayloadln(response oauth2.TokenResponse) {
	LogTokenPayload(response)
	pterm.Println()
}

func LogAuthMethod(config oauth2.ClientConfig) {
	switch config.AuthMethod {
	case oauth2.ClientSecretBasicAuthMethod:
		pterm.DefaultBox.WithTitle("Client Secret Basic").Printfln("Authorization = Basic BASE64-ENCODE(ClientID:ClientSecret)")
		pterm.Println()
	}
}
