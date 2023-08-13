package workers

import (
	"dnsScanner/helpers"
	"dnsScanner/models"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type spfOldWorker struct {
	next models.IDNSWorker
}

func (c *spfOldWorker) Execute(information models.WorkerInformation) []models.DnsWorkerResults {
	previousResults := c.next.Execute(information)

	r, previousResults := helpers.QueryDns(information, information.Hostname, previousResults, dns.TypeSPF, "SPF (old)")
	if r == nil {
		return previousResults
	}

	var workerResult models.OldSpfWorkerResult
	var results []models.SpfResult

	for _, a := range r.Answer {
		switch spf := a.(type) {
		case *dns.SPF:
			txtString := strings.Join(spf.Txt, "")
			total_number_lookups = 0
			total_number_of_failed_lookups = 0

			parserResults := parseSpfRecord(information.Client, information.DnsServer, dns.TypeSPF, information.Hostname, txtString, []string{information.Hostname})

			if total_number_lookups > 10 {
				parserResults.Validation = append(parserResults.Validation, models.AnalyzerResults{
					Severity: models.ERROR,
					Rule:     models.MORE_THAN_10_LOOKUPS,
					Message:  fmt.Sprintf("There were %d lookups", total_number_lookups),
				})
			}

			if total_number_of_failed_lookups > 2 {
				parserResults.Validation = append(parserResults.Validation, models.AnalyzerResults{
					Severity: models.WARNING,
					Rule:     models.TOTAL_FAILED_MORE_THAN_2,
					Message:  fmt.Sprintf("There were %d failed lookups", total_number_of_failed_lookups),
				})
			}

			results = append(results, parserResults)
		}
	}

	workerResult.Results = results

	previousResults = append(previousResults, workerResult)
	return previousResults
}

func (c *spfOldWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
