package analyze

import (
	"dnsScanner/models"
)

type redirectPosition struct {
	index int
	value models.RedirectSpfFragment
}

type redirectShouldNotAppearWithAllAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *redirectShouldNotAppearWithAllAnalyzer) Execute(parsedSpf []interface{}) []models.AnalyzerResults {
	var allHeaders []allPosition
	var redirectHeaders []redirectPosition
	var errors []models.AnalyzerResults

	for i, a := range parsedSpf {
		switch fragment := a.(type) {
		case models.AllSpfFragment:
			allHeaders = append(allHeaders, allPosition{
				index: i,
				value: fragment,
			})
		case models.RedirectSpfFragment:
			redirectHeaders = append(redirectHeaders, redirectPosition{
				index: i,
				value: fragment,
			})
		}
	}

	if len(allHeaders) != 0 && len(redirectHeaders) != 0 {
		errors = append(errors, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.ALL_WITH_REDIRECT,
			Message:  "The all mechanism cannot be present with redirect modifier!",
		})
	}

	results := append(c.next.Execute(parsedSpf), errors...)

	return results
}

func (c *redirectShouldNotAppearWithAllAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
