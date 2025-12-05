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

func (c *headerAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var headers []headerPosition
	var errors []models.AnalyzerResults

	for i, a := range analysisInfo.ParsedSpf {
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
			Severity:    models.ERROR,
			Rule:        models.NO_HEADER,
			Fixed:       false,
			FixedRecord: "",
			Message:     "No valid SPF header found!",
		})
	} else if len(headers) > 1 {
		errors = append(errors, models.AnalyzerResults{
			Severity:    models.ERROR,
			Rule:        models.MULTIPLE_HEADERS,
			Fixed:       false,
			FixedRecord: "",
			Message:     "Multiple SPF headers found!",
		})
	}

	if len(headers) != 0 {
		if headers[0].index != 0 {
			errors = append(errors, models.AnalyzerResults{
				Severity:    models.ERROR,
				Rule:        models.HEADER_NOT_FIRST,
				Fixed:       false,
				FixedRecord: "",
				Message:     "SPF header must be first!",
			})
		}
	}

	results := append(c.next.Execute(analysisInfo), errors...)

	return results
}

func (c *headerAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
