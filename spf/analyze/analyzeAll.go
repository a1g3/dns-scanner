package analyze

import (
	"dnsScanner/models"
	"fmt"
)

type allPosition struct {
	index int
	value models.AllSpfFragment
}

type allAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *allAnalyzer) Execute(parsedSpf []interface{}) []models.AnalyzerResults {
	var headers []allPosition
	var errors []models.AnalyzerResults

	for i, a := range parsedSpf {
		switch fragment := a.(type) {
		case models.AllSpfFragment:
			headers = append(headers, allPosition{
				index: i,
				value: fragment,
			})
		}
	}

	if len(headers) != 0 {
		if headers[0].index < len(parsedSpf)-1 {
			for i := headers[0].index + 1; i < len(parsedSpf); i++ {
				switch parsedSpf[i].(type) {
				case models.ExplanationSpfFragment, models.RedirectSpfFragment, models.UnparseableSpfFragment:
					continue
				default:
					errors = append(errors, models.AnalyzerResults{
						Severity: models.WARNING,
						Rule:     models.MECH_AFTER_ALL,
						Message:  fmt.Sprint("Mechanisms after all will be ignored."),
					})
				}
			}
		}
		if headers[0].value.Qualifier == models.Pass {
			errors = append(errors, models.AnalyzerResults{
				Severity: models.WARNING,
				Rule:     models.PASS_ALL,
				Message:  "Check the +all to ensure this is intended!",
			})
		}
	}

	results := append(c.next.Execute(parsedSpf), errors...)

	return results
}

func (c *allAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
