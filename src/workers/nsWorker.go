package workers

import (
	"dnsScanner/helpers"
	"dnsScanner/models"

	"github.com/miekg/dns"
)

type nsWorker struct {
	next models.IDNSWorker
}

func (c *nsWorker) execute(information models.WorkerInformation) []models.DnsWorkerResults {
	previousResults := c.next.Execute(information)

	r, previousResults := helpers.QueryDns(information, information.Hostname, previousResults, dns.TypeNS, "NS")
	if r == nil {
		return previousResults
	}

	results := models.NsWorkerResult{}

	for _, a := range r.Answer {
		switch ns := a.(type) {
		case *dns.NS:
			results.Records = append(results.Records, ns.String())
		}
	}

	previousResults = append(previousResults, results)
	return previousResults
}

func (c *nsWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
