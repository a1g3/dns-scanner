package parse

import (
	"dnsScanner/models"
	"strings"
)

func includeParser(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	include := models.IncludeSpfFragment{}
	include.Raw = raw
	include.Qualifier = qualifier
	include.Contents = strings.TrimPrefix(fragment, "include:")
	include.ContainsMacros = containsMacros(include.Contents)

	return include
}
