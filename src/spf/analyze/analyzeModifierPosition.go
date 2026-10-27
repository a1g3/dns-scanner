package analyze

import (
	"dnsScanner/models"
)

type modifiedPositionAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *modifiedPositionAnalyzer) Execute(parsedSpf []interface{}) []models.AnalyzerResults {
	hasSeenModifier := false
	var errors []models.AnalyzerResults

	for _, a := range parsedSpf {
		switch a.(type) {
		case models.ExplanationSpfFragment, models.RedirectSpfFragment:
			hasSeenModifier = true
		case models.UnparseableSpfFragment:
			continue
		default:
			if hasSeenModifier {
				errors = append(errors, models.AnalyzerResults{
					Severity: models.WARNING,
					Rule:     models.MECH_AFTER_MODIFIER,
					Message:  "Mechanisms should not appear after explanation or redirect modifiers.",
				})
				break
			}
		}
	}

	results := append(c.next.Execute(parsedSpf), errors...)

	return results
}

func (c *modifiedPositionAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
