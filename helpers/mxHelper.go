package helpers

import (
	"dnsScanner/models"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func ResolveMxRecord(client *dns.Client, dnsServer string, domain string) models.RecordReturn {
	fqdn := dns.Fqdn(domain)

	mxHelperModel := models.MxHelperModel{
		MxRecords:       []models.MxRecord{},
		NumberOfLookups: 0,
		Domain:          domain,
	}

	mxMsg := new(dns.Msg)
	mxMsg.SetQuestion(fqdn, dns.TypeMX)
	mxMsg.RecursionDesired = true

	mxRecord, _, _ := client.Exchange(mxMsg, dnsServer)
	mxHelperModel.NumberOfLookups += 1

	if mxRecord == nil {
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("Cannot resolve MX record for domain \"%s\"", fqdn),
		}
	}

	if mxRecord.Rcode != dns.RcodeSuccess {
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("MX record for domain \"%s\" did not return a successful RCODE", fqdn),
		}
	}

	for _, a := range mxRecord.Answer {
		switch answer := a.(type) {
		case *dns.MX:
			mxHelperModel.MxRecords = append(mxHelperModel.MxRecords, models.MxRecord{
				Raw:        answer.String(),
				Domain:     answer.Mx,
				Preference: answer.Preference,
				Error:      []models.AnalyzerResults{},
				Ips:        []net.IP{},
			})
		}
	}

	for i := range mxHelperModel.MxRecords {
		rec := ResolveARecord(client, dnsServer, mxHelperModel.MxRecords[i].Domain)
		mxHelperModel.NumberOfLookups += 1

		switch result := rec.(type) {
		case models.AnalyzerResults:
			mxHelperModel.MxRecords[i].Error = append(mxHelperModel.MxRecords[i].Error, result)
		case models.ARecord:
			mxHelperModel.MxRecords[i].Ips = result.Ips
		}
	}

	return mxHelperModel
}
