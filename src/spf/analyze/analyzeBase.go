package analyze

import "dnsScanner/models"

type baseAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *baseAnalyzer) Execute(_ []interface{}) []models.AnalyzerResults {
	var errors []models.AnalyzerResults

	return errors
}

func (c *baseAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
