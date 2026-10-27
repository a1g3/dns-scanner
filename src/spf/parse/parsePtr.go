package parse

import (
	"dnsScanner/models"
	"strings"
)

func ptrParse(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	ptrSpf := models.PtrSpfFragment{}
	ptrSpf.Raw = raw
	ptrSpf.Qualifier = qualifier

	if fragment == "ptr" {
		ptrSpf.Contents = ""
	} else if strings.HasPrefix(fragment, "ptr:") {
		ptrSpf.Contents = strings.TrimPrefix(fragment, "ptr:")
		ptrSpf.ContainsMacros = containsMacros(ptrSpf.Contents)
	} else {
		return parseError(raw, fragment, qualifier)
	}

	return ptrSpf
}
