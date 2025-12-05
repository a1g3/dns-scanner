package analyze

import (
	"dnsScanner/models"
)

type ptrDepercatedAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *ptrDepercatedAnalyzer) Execute(parsedSpf []interface{}, fixErrors bool) []models.AnalyzerResults {
	var errors []models.AnalyzerResults
	hasPtr := false

	ptr_index := 0
	for index, a := range parsedSpf {
		switch a.(type) {
		case models.PtrSpfFragment:
			hasPtr = true
			ptr_index = index
		}
	}

	if hasPtr {
		errors = append(errors, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.DEPRECATED_PTR,
			Message:  "The ptr mechanism is deprecated and should not be used!",
		})
	}

	if hasPtr && fixErrors {
		parsedSpf = append(parsedSpf[:ptr_index], parsedSpf[ptr_index+1:]...)
	}

	results := append(c.next.Execute(parsedSpf, fixErrors), errors...)

	return results
}

func (c *ptrDepercatedAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
