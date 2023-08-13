package workers

import (
	"dnsScanner/helpers"
	"dnsScanner/models"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type caaWorker struct {
	next models.IDNSWorker
}

func (c *caaWorker) Execute(information models.WorkerInformation) []models.DnsWorkerResults {
	previousResults := c.next.Execute(information)

	r, previousResults := helpers.QueryDns(information, information.Hostname, previousResults, dns.TypeCAA, "CAA")
	if r == nil {
		return previousResults
	}

	var result models.CaaWorkerResult

	for _, a := range r.Answer {
		switch caa := a.(type) {
		case *dns.CAA:
			result.Records = append(result.Records, caa.String())
			switch strings.TrimSpace(strings.ToLower(caa.Tag)) {
			case "issue":
				result.Issue = append(result.Issue, caa.Value)
			case "issuewild":
				result.IssueWild = append(result.IssueWild, caa.Value)
			case "iodef":
				result.Iodef = append(result.Iodef, caa.Value)
			case "contactemail":
				result.ContactEmail = append(result.ContactEmail, caa.Value)
			case "contactphone":
				result.ContactPhone = append(result.ContactPhone, caa.Value)
			default:
				fmt.Printf("ERROR: Unknown tag %s with a value of %s.\n", caa.Tag, caa.Value)
			}
		}
	}

	previousResults = append(previousResults, result)
	return previousResults
}

func (c *caaWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
