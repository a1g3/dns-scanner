package workers

import (
	"dnsScanner/helpers"
	"dnsScanner/models"
)

type mxWorker struct {
	next models.IDNSWorker
}

func (c *mxWorker) Execute(information models.WorkerInformation) []models.DnsWorkerResults {
	previousResults := c.next.Execute(information)

	mx := helpers.ResolveMxRecord(information.Client, information.DnsServer, information.Hostname)
	switch result := mx.(type) {
	case models.AnalyzerResults:
		previousResults = append(previousResults, models.DnsErrorResult{
			WorkerName: "MX",
			Error:      "Domain did not return a successful DNS response.",
		})
	case models.MxHelperModel:
		var records []string

		for _, rec := range result.MxRecords {
			records = append(records, rec.Raw)
		}

		previousResults = append(previousResults, models.MxWorkerResult{
			Mx:        result.MxRecords,
			DnsResult: models.DnsResult{Records: records},
		})
	}

	return previousResults
}

func (c *mxWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
