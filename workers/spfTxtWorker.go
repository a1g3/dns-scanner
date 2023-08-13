package workers

import (
	"dnsScanner/helpers"
	"dnsScanner/models"
	"dnsScanner/spf/analyze"
	"dnsScanner/spf/parse"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type spfTxtWorker struct {
	next models.IDNSWorker
}

var total_number_lookups = 0
var total_number_of_failed_lookups = 0

func (c *spfTxtWorker) Execute(information models.WorkerInformation) []models.DnsWorkerResults {
	previousResults := c.next.Execute(information)

	r, previousResults := helpers.QueryDns(information, information.Hostname, previousResults, dns.TypeTXT, "SPF")
	if r == nil {
		return previousResults
	}

	workerResult := models.SpfWorkerResult{}
	var results []models.SpfResult

	for _, a := range r.Answer {
		switch txt := a.(type) {
		case *dns.TXT:
			txtString := strings.Join(txt.Txt, "")
			if strings.HasPrefix(txtString, "v=spf1") {
				total_number_lookups = 0
				total_number_of_failed_lookups = 0
				parserResults := parseSpfRecord(information.Client, information.DnsServer, dns.TypeTXT, information.Hostname, txtString, []string{information.Hostname})

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
	}

	workerResult.Results = results

	previousResults = append(previousResults, workerResult)
	return previousResults
}

func parseSpfRecord(client *dns.Client, dnsServer string, dnsType uint16, domain string, spf string, domains []string) models.SpfResult {
	info := parse.ParseSpf(spf)
	var includes []models.IncludeSpfFragment
	var aSpf []models.ASpf
	var mxSpf []models.MxHelperModel
	var existsSpf []models.ASpf
	var redirects []models.RedirectSpfFragment

	validation := analyze.AnalyzeSpf(info)
	number := 0

	for _, a := range info {
		switch txt := a.(type) {
		case models.PtrSpfFragment:
			number = number + 1

		case models.RedirectSpfFragment:
			redirects = append(redirects, txt)
			number = number + 1

		case models.MxSpfFragment:
			number = number + 1
			if !txt.DomainSpec.ContainsMacros {
				aDomain := txt.Contents
				if txt.Contents == "" {
					aDomain = domain
				}

				mxRec := helpers.ResolveMxRecord(client, dnsServer, aDomain)
				switch v := mxRec.(type) {
				case models.AnalyzerResults:
					validation = append(validation, v)
				case models.MxHelperModel:
					mxSpf = append(mxSpf, v)
					for _, record := range v.MxRecords {
						if len(record.Error) > 0 {
							validation = append(validation, record.Error...)
						}
					}
				default:
					fmt.Errorf("Unknown resolveARecord return type")
				}
			}

		case models.ExistSpfFragment:
			number = number + 1
			if !txt.DomainSpec.ContainsMacros {
				existsDomain := txt.Contents
				fqdn := dns.Fqdn(existsDomain)

				aMsg := new(dns.Msg)
				aMsg.SetQuestion(fqdn, dns.TypeA)
				aMsg.RecursionDesired = true

				aRecord, _, _ := client.Exchange(aMsg, dnsServer)

				if aRecord == nil {
					validation = append(validation, models.AnalyzerResults{
						Severity: models.WARNING,
						Rule:     models.UNRESOLVEABLE_DOMAIN,
						Message:  fmt.Sprintf("Domain \"%s\" does not exist", fqdn),
					})
					continue
				}

				if aRecord.Rcode != dns.RcodeSuccess {
					validation = append(validation, models.AnalyzerResults{
						Severity: models.WARNING,
						Rule:     models.UNRESOLVEABLE_DOMAIN,
						Message:  fmt.Sprintf("Domain \"%s\" does not exist", fqdn),
					})
					continue
				}

				var ips []net.IP
				for _, a := range aRecord.Answer {
					switch answer := a.(type) {
					case *dns.A:
						ips = append(ips, answer.A)
					}
				}
				existsSpf = append(existsSpf, models.ASpf{
					Domain: existsDomain,
					Ips:    ips,
				})
			}

		case models.IncludeSpfFragment:
			includes = append(includes, txt)
			number = number + 1

		case models.ASpfFragment:
			if !txt.DomainSpec.ContainsMacros {
				aDomain := txt.Contents
				if txt.Contents == "" {
					aDomain = domain
				}

				record := helpers.ResolveARecord(client, dnsServer, aDomain)
				switch v := record.(type) {
				case models.AnalyzerResults:
					validation = append(validation, v)
				case models.ASpf:
					aSpf = append(aSpf, v)
				default:
					fmt.Errorf("Unknown resolveARecord return type")
				}
			}
			number = number + 1
		}
	}

	parsedRecord := models.SpfResult{
		Raw:             spf,
		Domain:          domain,
		Exists:          existsSpf,
		ASpf:            aSpf,
		Mx:              mxSpf,
		NumberOfLookups: number,
		Validation:      validation,
	}

	total_number_lookups += number

	for _, a := range includes {
		if a.ContainsMacros {
			parsedRecord.Includes = append(parsedRecord.Includes, models.SpfResult{Domain: a.Contents, Raw: a.Raw, NumberOfLookups: 0, Validation: []models.AnalyzerResults{}})
		} else {
			parsedRecord.Includes = append(parsedRecord.Includes, nsLookup(client, dnsServer, dnsType, a.Contents, domains))
		}
	}

	for _, a := range redirects {
		if a.ContainsMacros {
			parsedRecord.Redirects = append(parsedRecord.Redirects, models.SpfResult{Domain: a.Domain, Raw: a.Raw, NumberOfLookups: 0, Validation: []models.AnalyzerResults{}})
		} else {
			parsedRecord.Redirects = append(parsedRecord.Redirects, nsLookup(client, dnsServer, dnsType, a.Domain, domains))
		}
	}

	return parsedRecord
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if strings.EqualFold(a, e) {
			return true
		}
	}
	return false
}

func nsLookup(client *dns.Client, dnsServer string, dnsType uint16, domain string, domains []string) models.SpfResult {
	m := new(dns.Msg)
	fqdn := dns.Fqdn(domain)
	m.SetQuestion(fqdn, dnsType)
	m.RecursionDesired = true

	result := models.SpfResult{
		Raw:        "",
		Domain:     domain,
		Redirects:  []models.SpfResult{},
		Includes:   []models.SpfResult{},
		Validation: []models.AnalyzerResults{},
	}

	if contains(domains, fqdn) {
		result.Validation = append(result.Validation, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.CIRCULAR_REFERENCE,
			Message:  fmt.Sprintf("Circular reference detected with domain %s", domain),
		})

		return result
	}

	r, _, err := client.Exchange(m, dnsServer)
	if r == nil {
		total_number_of_failed_lookups = total_number_of_failed_lookups + 1
		result.Validation = append(result.Validation, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("Error: %s", err.Error()),
		})

		return result
	}

	if r.Rcode != dns.RcodeSuccess {
		total_number_of_failed_lookups = total_number_of_failed_lookups + 1
		result.Validation = append(result.Validation, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("No SPF records found for domain \"%s\" for type %d", fqdn, dnsType),
		})

		return result
	}

	foundSpf := false
	spfTxt := ""

	// Stuff must be in the answer section
	for _, a := range r.Answer {
		switch txt := a.(type) {
		case *dns.SPF:
		case *dns.TXT:
			txtString := strings.Join(txt.Txt, "")
			if strings.HasPrefix(txtString, "v=spf1") {
				result.Raw = txtString
				foundSpf = true
				spfTxt = txtString
			}
		}
	}

	if !foundSpf {
		result.Validation = append(result.Validation, models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("No SPF records found for domain \"%s\" for type %d", fqdn, dnsType),
		})

		return result
	}

	domains = append(domains, fqdn)

	return parseSpfRecord(client, dnsServer, dnsType, domain, spfTxt, domains)
}

func (c *spfTxtWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
