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

func (c *redirectShouldNotAppearWithAllAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var allHeaders []allPosition
	var redirectHeaders []redirectPosition
	var errors []models.AnalyzerResults

	for i, a := range analysisInfo.ParsedSpf {
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
			Severity:    models.ERROR,
			Rule:        models.ALL_WITH_REDIRECT,
			Fixed:       true,
			FixedRecord: "",
			Message:     "The all mechanism cannot be present with redirect modifier!",
		})

		if analysisInfo.FixRecord {
			// Remove all headers
			for j := len(allHeaders) - 1; j >= 0; j-- {
				index := allHeaders[j].index
				analysisInfo.ParsedSpf = append(analysisInfo.ParsedSpf[:index], analysisInfo.ParsedSpf[index+1:]...)
			}
		}
	}

	results := append(c.next.Execute(analysisInfo), errors...)

	return results
}

func (c *redirectShouldNotAppearWithAllAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
