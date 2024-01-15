package cmd

import (
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

var (
	Validate *validator.Validate
	Trans    ut.Translator
)

func init() {
	en := en.New()
	uni := ut.New(en, en)
	Trans, _ = uni.GetTranslator("en")

	Validate = validator.New()

	en_translations.RegisterDefaultTranslations(Validate, Trans)
}
