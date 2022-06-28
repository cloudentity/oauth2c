package cmd

import (
	"encoding/json"

	"github.com/pterm/pterm"
	"github.com/tidwall/pretty"
)

func LogJson(value interface{}) {
	output, err := json.Marshal(value)

	if err != nil {
		pterm.Error.Println(err)
		return
	}

	pterm.Println(string(pretty.Color(pretty.Pretty(output), nil)))
}
