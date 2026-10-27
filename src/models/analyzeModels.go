package models

type SpfValidationRule int

const (
	NO_HEADER                SpfValidationRule = 1
	MULTIPLE_HEADERS         SpfValidationRule = 2
	HEADER_NOT_FIRST         SpfValidationRule = 3
	UNKNOWN_MECH             SpfValidationRule = 4
	MECH_AFTER_ALL           SpfValidationRule = 5
	PASS_ALL                 SpfValidationRule = 6
	DEPRECATED_PTR           SpfValidationRule = 7
	ALL_WITH_REDIRECT        SpfValidationRule = 8
	MORE_THAN_10_LOOKUPS     SpfValidationRule = 9
	UNRESOLVEABLE_DOMAIN     SpfValidationRule = 10
	CIRCULAR_REFERENCE       SpfValidationRule = 11
	MECH_AFTER_MODIFIER      SpfValidationRule = 12
	TOTAL_FAILED_MORE_THAN_2 SpfValidationRule = 13
	BIG_IP_RANGE             SpfValidationRule = 14
	DUPLICATE_MODIFIER       SpfValidationRule = 15
)

type ValidationSeverity int

const (
	ERROR   ValidationSeverity = 1
	WARNING ValidationSeverity = 2
)

type RecordReturn interface{}

type AnalyzerResults struct {
	Severity ValidationSeverity
	Rule     SpfValidationRule
	Message  string

	RecordReturn
}

type ISPFAnalyzer interface {
	Execute(parsedSpf []interface{}) []AnalyzerResults
	SetNext(worker ISPFAnalyzer)
}

type DmarcValidationRule int

const (
	UNPARSABLE_RECORD  DmarcValidationRule = 1
	INVALID_NUMBER     DmarcValidationRule = 2
	POLICY_NONE        DmarcValidationRule = 3
	DUPLICATE_FRAGMENT DmarcValidationRule = 4
)

type DmarcAnalyzerResults struct {
	Severity ValidationSeverity
	Rule     DmarcValidationRule
	Message  string

	RecordReturn
}
