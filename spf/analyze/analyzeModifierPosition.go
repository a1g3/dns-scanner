package analyze

import (
	"dnsScanner/models"
)

type modifiedPositionAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *modifiedPositionAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	hasSeenModifier := false
	var errors []models.AnalyzerResults
	modifier_index := 0

	for index, a := range analysisInfo.ParsedSpf {
		switch a.(type) {
		case models.ExplanationSpfFragment, models.RedirectSpfFragment:
			if !hasSeenModifier {
				hasSeenModifier = true
				modifier_index = index
			}
		case models.UnparseableSpfFragment:
			continue
		default:
			if hasSeenModifier {
				errors = append(errors, models.AnalyzerResults{
					Severity: models.WARNING,
					Rule:     models.MECH_AFTER_MODIFIER,
					Fixed:    true,
					Message:  "Mechanisms should not appear after explanation or redirect modifiers.",
				})
				break
			}
		}
	}

	if hasSeenModifier && analysisInfo.FixRecord {
		// Create a slice to hold items that should be moved before the modifier
		var itemsToMove []models.ParsedSpfFragment

		// Iterate over elements after the modifier_index
		for i := modifier_index + 1; i < len(analysisInfo.ParsedSpf); i++ {
			switch analysisInfo.ParsedSpf[i].(type) {
			case models.ExplanationSpfFragment, models.RedirectSpfFragment:
				continue
			default:
				// Add item to itemsToMove and remove from the original position
				itemsToMove = append(itemsToMove, analysisInfo.ParsedSpf[i])
			}
		}

		// Remove the items that need to be moved from the original slice
		analysisInfo.ParsedSpf = append(analysisInfo.ParsedSpf[:modifier_index+1], analysisInfo.ParsedSpf[modifier_index+1+len(itemsToMove):]...)

		// Insert the items that should be moved before the modifier_index
		analysisInfo.ParsedSpf = append(analysisInfo.ParsedSpf[:modifier_index], append(itemsToMove, analysisInfo.ParsedSpf[modifier_index:]...)...)
	}

	results := append(c.next.Execute(analysisInfo), errors...)

	return results
}

func (c *modifiedPositionAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
