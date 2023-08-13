package helpers

import (
	"dnsScanner/models"
	"fmt"

	"github.com/miekg/dns"
)

func QueryDns(information models.WorkerInformation, hostname string, previousResults []models.DnsWorkerResults, dnstype uint16, workerName string) (*dns.Msg, []models.DnsWorkerResults) {
	var last_dns_rcode = -10
	var last_error error = nil
	for i := 0; i < 3; i++ {
		m := new(dns.Msg)
		m.SetQuestion(hostname, dnstype)
		m.RecursionDesired = true

		r, _, err := information.Client.Exchange(m, information.DnsServer)
		if r == nil {
			last_error = err
			continue
		}

		if r.Rcode == dns.RcodeSuccess {
			return r, previousResults
		}
		last_dns_rcode = r.Rcode
	}

	if last_error != nil {
		previousResults = append(previousResults, models.DnsErrorResult{
			WorkerName: workerName,
			Error:      fmt.Sprintf("Domain (%s) returned an error for record type %d. Error: %s", information.Hostname, last_error, last_error.Error()),
		})
	} else {
		previousResults = append(previousResults, models.DnsErrorResult{
			WorkerName: workerName,
			Error:      fmt.Sprintf("Domain (%s) did not return a successful DNS response (%d) for record type %d.", information.Hostname, last_dns_rcode, dnstype),
		})
	}

	return nil, previousResults
}
