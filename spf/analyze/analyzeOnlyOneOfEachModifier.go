package analyze

import (
	"dnsScanner/models"
)

type explanationPosition struct {
	index int
	value models.ExplanationSpfFragment
}

type onlyOneOfEachModifierAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *onlyOneOfEachModifierAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var explanationHeaders []explanationPosition
	var redirectHeaders []redirectPosition
	var errors []models.AnalyzerResults

	for i, a := range analysisInfo.ParsedSpf {
		switch fragment := a.(type) {
		case models.ExplanationSpfFragment:
			explanationHeaders = append(explanationHeaders, explanationPosition{
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

	if len(redirectHeaders) > 1 {
		errors = append(errors, models.AnalyzerResults{
			Severity:    models.ERROR,
			Rule:        models.DUPLICATE_MODIFIER,
			Fixed:       false,
			FixedRecord: "",
			Message:     "Only one redirect modifier can appear in a SPF record!",
		})
	}

	if len(explanationHeaders) > 1 {
		errors = append(errors, models.AnalyzerResults{
			Severity:    models.ERROR,
			Rule:        models.DUPLICATE_MODIFIER,
			Fixed:       false,
			FixedRecord: "",
			Message:     "Only one explanation modifier can appear in a SPF record!",
		})
	}

	results := append(c.next.Execute(analysisInfo), errors...)

	return results
}

func (c *onlyOneOfEachModifierAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
