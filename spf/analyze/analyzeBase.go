package analyze

import (
	"dnsScanner/models"
	"fmt"
	"strings"
)

type baseAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *baseAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var errors []models.AnalyzerResults
	result := ""

	for _, a := range analysisInfo.ParsedSpf {
		fmt.Printf("Type of a: %T\n", a)
		if val, ok := a.(models.SpfFragment); ok {
			result += val.ToString() + " "
		}
	}
	result = strings.TrimSpace(result)
	fmt.Println("Fixed SPF: " + result)

	return errors
}

func (c *baseAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
