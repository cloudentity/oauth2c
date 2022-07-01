package cmd

import "github.com/pterm/pterm"

func PromptBool(name string) (ret bool) {
	pterm.Println(name + ":")
	ret, _ = pterm.DefaultInteractiveConfirm.Show()
	pterm.Println()

	return ret
}

func PromptString(name string) (ret string) {
	for ret == "" {
		pterm.Println(name + ":")
		ret, _ = pterm.DefaultInteractiveTextInput.Show()
		pterm.Println()

		if ret == "" {
			pterm.Warning.Printfln("%s is required", name)
		}
	}

	return ret
}

func PromptStringSlice(name string, options []string) (ret string) {
	for ret == "" {
		pterm.Println(name + ":")
		ret, _ = pterm.DefaultInteractiveSelect.WithOptions(options).Show()

		if ret == "" {
			pterm.Println()
			pterm.Warning.Printfln("%s is required", name)
		}
	}

	return ret
}

func PromptMultiStringSlice(name string, options []string) (ret []string) {
	for len(ret) == 0 {
		pterm.Println(name + ":")
		ret, _ = pterm.DefaultInteractiveMultiselect.WithOptions(options).Show()

		if len(ret) == 0 {
			pterm.Println()
			pterm.Warning.Printfln("%s is required", name)
		}
	}

	return ret
}
