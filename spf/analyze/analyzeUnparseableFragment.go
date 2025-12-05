package analyze

import (
	"dnsScanner/models"
	"fmt"
)

type unparseableAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *unparseableAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var headers []models.UnparseableSpfFragment
	var errors []models.AnalyzerResults
	var unparseableIndexes []int

	for index, a := range analysisInfo.ParsedSpf {
		switch fragment := a.(type) {
		case models.UnparseableSpfFragment:
			headers = append(headers, fragment)
			unparseableIndexes = append(unparseableIndexes, index)
		}
	}

	for _, a := range headers {
		errors = append(errors, models.AnalyzerResults{
			Severity: models.WARNING,
			Rule:     models.UNKNOWN_MECH,
			Message:  fmt.Sprintf("Unknown fragment \"%s\"", a.Raw),
		})
	}

	if unparseableIndexes != nil && analysisInfo.FixRecord {
		for i := len(unparseableIndexes) - 1; i >= 0; i-- {
			index := unparseableIndexes[i]
			analysisInfo.ParsedSpf = append(analysisInfo.ParsedSpf[:index], analysisInfo.ParsedSpf[index+1:]...)
		}
	}

	results := append(c.next.Execute(analysisInfo), errors...)

	return results
}

func (c *unparseableAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
