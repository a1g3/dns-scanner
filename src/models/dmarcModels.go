package models

type Visitor interface {
	VisitDmarc(*DMARC)
	VisitSrequest(*SrequestFragment)
	VisitDkim(*ADkimFragment)
	VisitSpf(*ADSpfFragment)
	VisitAInterval(*AIntervalFragment)
	VisitFailureOptions(*FailureOptionsFragment)
	VisitFormat(*FormatFragment)
	VisitReportAggregate(*ReportAggregateFragment)
	VisitReportFailure(*ReportFailureFragment)
	VisitPercent(*PercentFragment)
}

type DmarcFragment interface {
	Accept(Visitor)
}

type SrequestFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value string                  `"sp" whitespace* "=" whitespace* @( "none" | "quarantine" | "reject" )`

	Next *DmarcFragment `(@@)?`
}

func (t SrequestFragment) Accept(v Visitor) { v.VisitSrequest(&t) }

type ADkimFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value string                  `"adkim" whitespace* "=" whitespace* @( "r" | "s" )`

	Next *DmarcFragment `(@@)?`
}

func (t ADkimFragment) Accept(v Visitor) { v.VisitDkim(&t) }

type ADSpfFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value string                  `"aspf" whitespace* "=" whitespace* @( "r" | "s" )`

	Next *DmarcFragment `(@@)?`
}

func (t ADSpfFragment) Accept(v Visitor) { v.VisitSpf(&t) }

type AIntervalFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value int                     `"ri" whitespace* "=" whitespace* @Number`

	Next *DmarcFragment `(@@)?`
}

func (t AIntervalFragment) Accept(v Visitor) { v.VisitAInterval(&t) }

type PercentFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value int                     `"pct" whitespace* "=" whitespace* @Number`

	Next *DmarcFragment `(@@)?`
}

func (t PercentFragment) Accept(v Visitor) { v.VisitPercent(&t) }

type FailureOptionsFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value string                  `"fo" whitespace* "=" whitespace* @(( "0" | "1" | "d" | "s" ) ( whitespace* ":" whitespace* ("0" | "1" | "d" | "s" ) )*)`

	Next *DmarcFragment `(@@)?`
}

func (t FailureOptionsFragment) Accept(v Visitor) { v.VisitFailureOptions(&t) }

type FormatFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value string                  `"rf" whitespace* "=" whitespace* @(((Chars | Number | "-" )+) (whitespace* ":" (( Chars | Number | "-" )+))* )`

	Next *DmarcFragment `(@@)?`
}

func (t FormatFragment) Accept(v Visitor) { v.VisitFormat(&t) }

type ReportAggregateFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value string                  `"rua" whitespace* "=" whitespace* @((Chars | Number | Punct)+ (whitespace* "," whitespace* (Chars | Number | Punct)+)*)`

	Next *DmarcFragment `(@@)?`
}

func (t ReportAggregateFragment) Accept(v Visitor) { v.VisitReportAggregate(&t) }

type ReportFailureFragment struct {
	Sep   *SeparatorDmarcFragment `@@`
	Value string                  `"ruf" whitespace* "=" whitespace* @((Chars | Number | Punct)+ (whitespace* "," whitespace* (Chars | Number | Punct)+)*)`

	Next *DmarcFragment `(@@)?`
}

func (t ReportFailureFragment) Accept(v Visitor) { v.VisitReportFailure(&t) }

type HeaderDmarcFragment struct {
	Contents string `"v" whitespace* "=" whitespace* "DMARC1"`
}

type DmarcRequestFragment struct {
	Sep    *SeparatorDmarcFragment `@@`
	Policy string                  `"p" whitespace* "=" whitespace* @( "none" | "quarantine" | "reject" )`
}

type SeparatorDmarcFragment struct {
	Contents string `whitespace* ";" whitespace*`
}

type DMARC struct {
	Header  *HeaderDmarcFragment    `@@`
	Request *DmarcRequestFragment   `(@@)?`
	Frag    *DmarcFragment          `(@@)?`
	Sep     *SeparatorDmarcFragment `(@@)?`
}

func (t DMARC) Accept(v Visitor) { v.VisitDmarc(&t) }
