package parse

import (
	"dnsScanner/models"
	"strings"
)

func mxParser(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	mxSpf := models.MxSpfFragment{}
	mxSpf.Raw = raw
	mxSpf.Qualifier = qualifier

	if fragment == "mx" {
		mxSpf.Contents = ""
	} else if strings.HasPrefix(fragment, "mx:") {
		mxSpf.Contents = strings.TrimPrefix(fragment, "mx:")
		mxSpf.ContainsMacros = containsMacros(mxSpf.Contents)
	} else if strings.HasPrefix(fragment, "mx/") {
		mxSpf.Contents = strings.TrimPrefix(fragment, "mx")
	} else {
		return parseError(raw, fragment, qualifier)
	}

	return mxSpf
}
