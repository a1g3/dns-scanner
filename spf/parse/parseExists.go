package parse

import (
	"dnsScanner/models"
	"strings"
)

func existsParser(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	existsSpf := models.ExistSpfFragment{}
	existsSpf.Raw = raw
	existsSpf.Qualifier = qualifier
	existsSpf.Contents = strings.TrimPrefix(fragment, "exists:")
	existsSpf.ContainsMacros = containsMacros(existsSpf.Contents)

	return existsSpf
}
