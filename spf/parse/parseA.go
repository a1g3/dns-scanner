package parse

import (
	"dnsScanner/models"
	"strings"
)

func aParser(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	aSpf := models.ASpfFragment{}
	aSpf.Raw = raw
	aSpf.Qualifier = qualifier
	aSpf.ContainsMacros = false

	if fragment == "a" {
		aSpf.Contents = ""
	} else if strings.HasPrefix(fragment, "a:") {
		aSpf.Contents = strings.TrimPrefix(fragment, "a:")
		aSpf.ContainsMacros = containsMacros(aSpf.Contents)
	} else if strings.HasPrefix(fragment, "a/") {
		aSpf.Contents = strings.TrimPrefix(fragment, "a")
	} else {
		return parseError(raw, fragment, qualifier)
	}

	return aSpf
}
