package analyze

import (
	"dnsScanner/models"
)

type ptrDepercatedAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *ptrDepercatedAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var errors []models.AnalyzerResults
	hasPtr := false

	ptr_index := 0
	for index, a := range analysisInfo.ParsedSpf {
		switch a.(type) {
		case models.PtrSpfFragment:
			hasPtr = true
			ptr_index = index
		}
	}

	if hasPtr {
		errors = append(errors, models.AnalyzerResults{
			Severity:    models.ERROR,
			Rule:        models.DEPRECATED_PTR,
			Fixed:       true,
			FixedRecord: "",
			Message:     "The ptr mechanism is deprecated and should not be used!",
		})
	}

	if hasPtr && analysisInfo.FixRecord {
		analysisInfo.ParsedSpf = append(analysisInfo.ParsedSpf[:ptr_index], analysisInfo.ParsedSpf[ptr_index+1:]...)
	}

	results := append(c.next.Execute(analysisInfo), errors...)
	return results
}

func (c *ptrDepercatedAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
