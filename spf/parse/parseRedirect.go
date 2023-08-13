package parse

import (
	"dnsScanner/models"
	"strings"
)

func redirectParser(raw string, fragment string, _ models.Qualifier) models.ParsedSpfFragment {
	redirectSpf := models.RedirectSpfFragment{}
	redirectSpf.Raw = raw
	redirectSpf.Domain = strings.TrimPrefix(fragment, "redirect=")
	redirectSpf.ContainsMacros = containsMacros(redirectSpf.Domain)

	return redirectSpf
}
