package parse

import (
	"dnsScanner/models"
	"strings"
)

func ParseSpf(record string) []interface{} {
	var parsedRecords []interface{}

	fragments := strings.Split(record, " ")

	for i := range fragments {
		qual := models.Pass
		raw := fragments[i]
		fragment := strings.Trim(strings.ToLower(fragments[i]), " ")

		if strings.HasPrefix(fragment, "+") {
			qual = models.Pass
			fragment = strings.Trim(fragment, "+")
		} else if strings.HasPrefix(fragment, "-") {
			qual = models.HardFail
			fragment = strings.Trim(fragment, "-")
		} else if strings.HasPrefix(fragment, "~") {
			qual = models.SoftFail
			fragment = strings.Trim(fragment, "~")
		} else if strings.HasPrefix(fragment, "?") {
			qual = models.Neutral
			fragment = strings.Trim(fragment, "?")
		}

		if fragment == "v=spf1" {
			parsedRecords = append(parsedRecords, headerParser(raw, fragment, qual))
		} else if fragment == "all" {
			parsedRecords = append(parsedRecords, allParser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "ip4:") {
			parsedRecords = append(parsedRecords, ip4Parser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "include:") {
			parsedRecords = append(parsedRecords, includeParser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "a") {
			parsedRecords = append(parsedRecords, aParser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "mx") {
			parsedRecords = append(parsedRecords, mxParser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "ip6:") {
			parsedRecords = append(parsedRecords, ip6Parser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "exists:") {
			parsedRecords = append(parsedRecords, existsParser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "ptr") {
			parsedRecords = append(parsedRecords, ptrParse(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "redirect=") {
			parsedRecords = append(parsedRecords, redirectParser(raw, fragment, qual))
		} else if strings.HasPrefix(fragment, "exp=") {
			parsedRecords = append(parsedRecords, expParser(raw, fragment, qual))
		} else if fragment == "" {
			continue
		} else {
			parsedRecords = append(parsedRecords, parseError(raw, fragment, qual))
		}

	}

	return parsedRecords
}
