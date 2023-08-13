package parse

import (
	"dnsScanner/models"
)

func headerParser(raw string, _ string, _ models.Qualifier) models.ParsedSpfFragment {
	header := models.HeaderSpfFragment{}
	header.Contents = raw

	return header
}
