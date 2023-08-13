package analyze

import (
	"dnsScanner/models"
)

type ptrDepercatedAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *ptrDepercatedAnalyzer) Execute(parsedSpf []interface{}) []models.AnalyzerResults {
	var errors []models.AnalyzerResults
	hasPtr := false

	for _, a := range parsedSpf {
		switch a.(type) {
		case models.PtrSpfFragment:
			hasPtr = true
		}
	}

	if hasPtr {
		errors = append(errors, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.DEPRECATED_PTR,
			Message:  "The ptr mechanism is deprecated and should not be used!",
		})
	}

	results := append(c.next.Execute(parsedSpf), errors...)

	return results
}

func (c *ptrDepercatedAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
