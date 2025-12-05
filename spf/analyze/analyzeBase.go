package analyze

import (
	"dnsScanner/models"
	"fmt"
	"strings"
)

type baseAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *baseAnalyzer) Execute(parsedSpf []interface{}, _ bool) []models.AnalyzerResults {
	var errors []models.AnalyzerResults
	result := ""

	for _, a := range parsedSpf {
		fmt.Printf("Type of a: %T\n", a)
		if val, ok := a.(models.ToString); ok {
			fmt.Println("Here!" + result)
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
