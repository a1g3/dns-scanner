package parse

import (
	"dnsScanner/models"
	"strings"
)

func expParser(raw string, fragment string, _ models.Qualifier) models.ParsedSpfFragment {
	redirectSpf := models.ExplanationSpfFragment{}
	redirectSpf.Raw = raw
	redirectSpf.Domain = strings.TrimPrefix(fragment, "exp=")

	return redirectSpf
}
