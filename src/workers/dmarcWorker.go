package workers

import (
	"dnsScanner/dmarc/analyze"
	"dnsScanner/dmarc/parse"
	"dnsScanner/helpers"
	"dnsScanner/models"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type dmarcWorker struct {
	next models.IDNSWorker
}

func (c *dmarcWorker) Execute(information models.WorkerInformation) []models.DnsWorkerResults {
	previousResults := c.next.Execute(information)

	r, previousResults := helpers.QueryDns(information, "_dmarc."+information.Hostname, previousResults, dns.TypeTXT, "DMARC")
	if r == nil {
		return previousResults
	}

	result := models.DmarcWorkerResult{}

	for _, a := range r.Answer {
		switch txt := a.(type) {
		case *dns.TXT:
			txtString := strings.Join(txt.Txt, "")
			result.Records = append(result.Records, txtString)

			ast, err := parse.ParseDmarc(txtString)
			if err != nil {
				result.Validation = append(result.Validation, models.DmarcAnalyzerResults{
					Severity: models.ERROR,
					Rule:     models.UNPARSABLE_RECORD,
					Message:  fmt.Sprintf("Error parsing the record: %s", err.Error()),
				})
				continue
			}
			analyzer := analyze.DmarcVisitor{}
			analyzer.VisitDmarc(ast)

			result.Request = analyzer.Request
			result.ADkim = analyzer.ADkim
			result.ASpf = analyzer.ASpf
			result.SRequest = analyzer.SRequest
			result.AInterval = analyzer.AInterval
			result.Percent = analyzer.Percent
			result.FailureOptions = analyzer.FailureOptions
			result.FormatFragment = analyzer.FormatFragment
			result.ReportAggregate = analyzer.ReportAggregate
			result.ReportFailure = analyzer.ReportFailure
		}
	}

	previousResults = append(previousResults, result)
	return previousResults
}

func (c *dmarcWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
