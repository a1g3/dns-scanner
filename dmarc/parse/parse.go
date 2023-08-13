package parse

import (
	"dnsScanner/models"

	"github.com/alecthomas/participle/v2"
	"github.com/alecthomas/participle/v2/lexer"
)

func ParseDmarc(record string) (*models.DMARC, error) {
	iniLexer := lexer.MustSimple([]lexer.SimpleRule{
		{"String", `"(\\"|[^"])*"`},
		{"Number", `\d+`},
		{"Chars", `[a-zA-Z_]\w*`},
		{"Semi", `;`},
		{"Punct", `[-[!@#$%^&*()+_={}\|,:"'<>.?/]|]`},
		{"whitespace", `[\t|\s]*`},
	})

	parser := participle.MustBuild[models.DMARC](
		participle.Lexer(iniLexer),
		participle.Union[models.DmarcFragment](models.ADkimFragment{}, models.SrequestFragment{}, models.ADSpfFragment{}, models.AIntervalFragment{}, models.PercentFragment{}, models.FailureOptionsFragment{}, models.FormatFragment{}, models.ReportAggregateFragment{}, models.ReportFailureFragment{}),
	)

	opts := participle.AllowTrailing(false)

	ini, err := parser.ParseString("", record, opts)

	if err != nil {
		return nil, err
	}

	return ini, nil
}
