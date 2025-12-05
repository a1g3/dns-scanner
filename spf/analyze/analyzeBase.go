package analyze

import (
	"dnsScanner/models"
	"strings"
)

type baseAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *baseAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var errors []models.AnalyzerResults
	result := ""

	if analysisInfo.FixRecord {
		for _, a := range analysisInfo.ParsedSpf {
			result += a.ToString() + " "
		}
		result = strings.TrimSpace(result)

		errors = append(errors, models.AnalyzerResults{
			Severity:    models.INFO,
			Rule:        models.FIXED_RECORD,
			Fixed:       true,
			FixedRecord: result,
			Message:     "",
		})
	}

	return errors
}

func (c *baseAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
