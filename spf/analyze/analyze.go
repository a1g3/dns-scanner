package analyze

import "dnsScanner/models"

func AnalyzeSpf(parsedSpf []interface{}, fixErrors bool) []models.AnalyzerResults {
	analysisInfo := models.AnalysisInfo{
		ParsedSpf: parsedSpf,
		FixRecord: fixErrors,
	}

	base := &baseAnalyzer{}

	header := &headerAnalyzer{}
	header.SetNext(base)

	unparseable := &unparseableAnalyzer{}
	unparseable.SetNext(header)

	all := &allAnalyzer{}
	all.SetNext(unparseable)

	ptr := &ptrDepercatedAnalyzer{}
	ptr.SetNext(all)

	redirect := &redirectShouldNotAppearWithAllAnalyzer{}
	redirect.SetNext(ptr)

	//ip := &ipLengthAnalyzer{}
	//ip.SetNext(redirect)

	onlyOneOfEachModifier := &onlyOneOfEachModifierAnalyzer{}
	onlyOneOfEachModifier.SetNext(redirect)

	modifiedPosition := &modifiedPositionAnalyzer{}
	modifiedPosition.SetNext(onlyOneOfEachModifier)

	return modifiedPosition.Execute(analysisInfo)
}
