package analyze

import (
	"dnsScanner/models"
)

type headerPosition struct {
	index int
	value models.HeaderSpfFragment
}

type headerAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *headerAnalyzer) Execute(parsedSpf []interface{}) []models.AnalyzerResults {
	var headers []headerPosition
	var errors []models.AnalyzerResults

	for i, a := range parsedSpf {
		switch fragment := a.(type) {
		case models.HeaderSpfFragment:
			headers = append(headers, headerPosition{
				index: i,
				value: fragment,
			})
		}
	}

	if len(headers) == 0 {
		errors = append(errors, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.NO_HEADER,
			Message:  "No valid SPF header found!",
		})
	} else if len(headers) > 1 {
		errors = append(errors, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.MULTIPLE_HEADERS,
			Message:  "Multiple SPF headers found!",
		})
	}

	if len(headers) != 0 {
		if headers[0].index != 0 {
			errors = append(errors, models.AnalyzerResults{
				Severity: models.ERROR,
				Rule:     models.HEADER_NOT_FIRST,
				Message:  "SPF header must be first!",
			})
		}
	}

	results := append(c.next.Execute(parsedSpf), errors...)

	return results
}

func (c *headerAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
