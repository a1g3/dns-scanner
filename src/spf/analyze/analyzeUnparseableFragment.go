package analyze

import (
	"dnsScanner/models"
	"fmt"
)

type unparseableAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *unparseableAnalyzer) Execute(parsedSpf []interface{}) []models.AnalyzerResults {
	var headers []models.UnparseableSpfFragment
	var errors []models.AnalyzerResults

	for _, a := range parsedSpf {
		switch fragment := a.(type) {
		case models.UnparseableSpfFragment:
			headers = append(headers, fragment)
		}
	}

	for _, a := range headers {
		errors = append(errors, models.AnalyzerResults{
			Severity: models.WARNING,
			Rule:     models.UNKNOWN_MECH,
			Message:  fmt.Sprintf("Unknown fragment \"%s\"", a.Raw),
		})
	}

	results := append(c.next.Execute(parsedSpf), errors...)

	return results
}

func (c *unparseableAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
