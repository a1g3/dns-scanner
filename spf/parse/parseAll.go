package parse

import (
	"dnsScanner/models"
)

func allParser(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	allMech := models.AllSpfFragment{}
	allMech.Raw = raw
	allMech.Qualifier = qualifier
	allMech.Contents = fragment

	return allMech
}
