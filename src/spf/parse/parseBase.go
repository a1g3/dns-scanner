package parse

import (
	"dnsScanner/models"
	"regexp"
)

func parseError(raw string, _ string, _ models.Qualifier) models.ParsedSpfFragment {
	errFrag := models.UnparseableSpfFragment{}
	errFrag.Raw = raw

	return errFrag
}

func containsMacros(raw string) bool {
	var validID = regexp.MustCompile(`%{.*}`)
	isValid := validID.MatchString(raw)

	return isValid
}
