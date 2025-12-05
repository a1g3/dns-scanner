package analyze

import (
	"dnsScanner/models"
)

type allPosition struct {
	index int
	value models.AllSpfFragment
}

type allAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *allAnalyzer) Execute(analysisInfo *models.AnalysisInfo) []models.AnalyzerResults {
	var headers []allPosition
	var errors []models.AnalyzerResults

	for i, a := range analysisInfo.ParsedSpf {
		switch fragment := a.(type) {
		case models.AllSpfFragment:
			headers = append(headers, allPosition{
				index: i,
				value: fragment,
			})
		}
	}

	if len(headers) != 0 {
		if headers[0].index < len(analysisInfo.ParsedSpf)-1 {
			for i := headers[0].index + 1; i < len(analysisInfo.ParsedSpf); i++ {
				switch analysisInfo.ParsedSpf[i].(type) {
				case models.ExplanationSpfFragment, models.RedirectSpfFragment, models.UnparseableSpfFragment:
					continue
				default:
					// AG TODO:  Add fix for this
					errors = append(errors, models.AnalyzerResults{
						Severity:    models.WARNING,
						Rule:        models.MECH_AFTER_ALL,
						Fixed:       true,
						FixedRecord: "",
						Message:     "Mechanisms after all will be ignored.",
					})
				}
			}
		}
		if headers[0].value.Qualifier == models.Pass {
			errors = append(errors, models.AnalyzerResults{
				Severity:    models.WARNING,
				Rule:        models.PASS_ALL,
				Fixed:       false,
				FixedRecord: "",
				Message:     "Check the +all to ensure this is intended!",
			})
		}
	}

	results := append(c.next.Execute(analysisInfo), errors...)

	return results
}

func (c *allAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
