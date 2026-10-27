package helpers

import (
	"dnsScanner/models"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func ResolveARecord(client *dns.Client, dnsServer string, domain string) models.RecordReturn {
	fqdn := dns.Fqdn(domain)

	aSpf := models.ARecord{
		Domain: domain,
		Ips:    []net.IP{},
	}
	hasARecord := true
	hasAAAARecord := true

	aMsg := new(dns.Msg)
	aMsg.SetQuestion(fqdn, dns.TypeA)
	aMsg.RecursionDesired = true

	aaaaMsg := new(dns.Msg)
	aaaaMsg.SetQuestion(fqdn, dns.TypeAAAA)
	aaaaMsg.RecursionDesired = true

	aRecord, _, _ := client.Exchange(aMsg, dnsServer)
	aaaaRecord, _, _ := client.Exchange(aaaaMsg, dnsServer)

	print(fqdn + "\n")

	if aRecord == nil && aaaaRecord == nil {
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("Error for A and AAAA record"),
		}
	}

	if aRecord != nil {
		if aRecord.Rcode != dns.RcodeSuccess {
			hasARecord = false
		} else {
			for _, a := range aRecord.Answer {
				switch answer := a.(type) {
				case *dns.A:
					aSpf.Ips = append(aSpf.Ips, answer.A)
				}
			}
		}
	}

	if aaaaRecord != nil {
		if aaaaRecord.Rcode != dns.RcodeSuccess {
			hasAAAARecord = false
		} else {
			for _, a := range aaaaRecord.Answer {
				switch answer := a.(type) {
				case *dns.AAAA:
					aSpf.Ips = append(aSpf.Ips, answer.AAAA)
				}
			}
		}
	}

	if !(hasAAAARecord || hasARecord) {
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("A record for domain \"%s\" is not resolved", fqdn),
		}
	}

	return aSpf
}
