package workers

import (
	"dnsScanner/helpers"
	"dnsScanner/models"

	"github.com/miekg/dns"
)

type dnskeyWorker struct {
	next models.IDNSWorker
}

func (c *dnskeyWorker) Execute(information models.WorkerInformation) []models.DnsWorkerResults {
	previousResults := c.next.Execute(information)

	r, previousResults := helpers.QueryDns(information, information.Hostname, previousResults, dns.TypeDNSKEY, "DNSKEY")
	if r == nil {
		return previousResults
	}

	results := models.DnssecWorkerResult{}

	for _, a := range r.Answer {
		switch dnsKey := a.(type) {
		case *dns.DNSKEY:
			results.Records = append(results.Records, dnsKey.String())
		}
	}

	previousResults = append(previousResults, results)

	return previousResults
}

func (c *dnskeyWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
