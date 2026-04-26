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
			results = c.ParseAndAnalyzeSpf(txtString, information, results)
		}
	}

	workerResult.Results = results

	previousResults = append(previousResults, workerResult)
	return previousResults
}

func (*spfTxtWorker) ParseAndAnalyzeSpf(txtString string, information models.WorkerInformation, results []models.SpfResult) []models.SpfResult {
	if strings.HasPrefix(txtString, "v=spf1") {
		total_number_lookups = 0
		total_number_of_failed_lookups = 0
		parserResults := parseSpfRecord(information.Client, information.DnsServer, dns.TypeTXT, information.Hostname, txtString, []string{information.Hostname}, information.FixErrors)

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
	return results
}

func parseSpfRecord(client *dns.Client, dnsServer string, dnsType uint16, domain string, spf string, domains []string, fixErrors bool) models.SpfResult {
	info := parse.ParseSpf(spf)
	var includes []models.IncludeSpfFragment
	var aSpf []models.ASpf
	var mxSpf []models.MxHelperModel
	var existsSpf []models.ASpf
	var redirects []models.RedirectSpfFragment

	var analysisInfo = &models.AnalysisInfo{
		ParsedSpf: info,
		FixRecord: fixErrors,
	}

	validation := analyze.AnalyzeSpf(analysisInfo)
	number := 0
	var itemsToRemove []int

	for index, a := range info {
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
					if analysisInfo.FixRecord {
						itemsToRemove = append(itemsToRemove, index)
						v.Fixed = true
					}
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
					v := models.AnalyzerResults{
						Severity: models.WARNING,
						Rule:     models.UNRESOLVEABLE_DOMAIN,
						Message:  fmt.Sprintf("Domain \"%s\" does not exist", fqdn),
					}

					if analysisInfo.FixRecord {
						itemsToRemove = append(itemsToRemove, index)
						v.Fixed = true
					}

					validation = append(validation, v)

					continue
				}

				if aRecord.Rcode != dns.RcodeSuccess {
					v := models.AnalyzerResults{
						Severity: models.WARNING,
						Rule:     models.UNRESOLVEABLE_DOMAIN,
						Message:  fmt.Sprintf("Domain \"%s\" does not exist", fqdn),
					}

					if analysisInfo.FixRecord {
						itemsToRemove = append(itemsToRemove, index)
						v.Fixed = true
					}

					validation = append(validation, v)

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
					if analysisInfo.FixRecord {
						itemsToRemove = append(itemsToRemove, index)
						v.Fixed = true
					}
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

	for i := len(itemsToRemove) - 1; i >= 0; i-- {
		idx := itemsToRemove[i]
		info = append(info[:idx], info[idx+1:]...)
	}

	for i, _ := range validation {
		if validation[i].Rule == models.FIXED_RECORD {
			result := ""
			for _, a := range info {
				result += a.ToString() + " "
			}
			result = strings.TrimSpace(result)
			validation[i].FixedRecord = result
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
			err, lookup := nsLookup(client, dnsServer, dnsType, a.Contents, domains, false)

			// AG TODO: Handle fixing circular references and unresolveable domains here
			if err.Severity != models.OK {
				parsedRecord.Validation = append(parsedRecord.Validation, err)
				continue
			}

			parsedRecord.Includes = append(parsedRecord.Includes, lookup)
		}
	}

	for _, a := range redirects {
		if a.ContainsMacros {
			parsedRecord.Redirects = append(parsedRecord.Redirects, models.SpfResult{Domain: a.Domain, Raw: a.Raw, NumberOfLookups: 0, Validation: []models.AnalyzerResults{}})
		} else {
			err, lookup := nsLookup(client, dnsServer, dnsType, a.Domain, domains, false)

			// AG TODO: Handle fixing circular references and unresolveable domains here
			if err.Severity != models.OK {
				parsedRecord.Validation = append(parsedRecord.Validation, err)
				continue
			}

			parsedRecord.Redirects = append(parsedRecord.Redirects, lookup)
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

// Change this function to return an error or an SPF Result
func nsLookup(client *dns.Client, dnsServer string, dnsType uint16, domain string, domains []string, fixErrors bool) (models.AnalyzerResults, models.SpfResult) {
	m := new(dns.Msg)
	foundSpf := false
	spfTxt := ""
	fqdn := dns.Fqdn(domain)

	m.SetQuestion(fqdn, dnsType)
	m.RecursionDesired = true

	if contains(domains, fqdn) {
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.CIRCULAR_REFERENCE,
			Message:  fmt.Sprintf("Circular reference detected with domain %s", domain),
		}, models.SpfResult{}
	}

	r, _, err := client.Exchange(m, dnsServer)
	if r == nil {
		total_number_of_failed_lookups = total_number_of_failed_lookups + 1
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("Error: %s", err.Error()),
		}, models.SpfResult{}
	}

	if r.Rcode != dns.RcodeSuccess {
		total_number_of_failed_lookups = total_number_of_failed_lookups + 1
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("No SPF records found for domain \"%s\" for type %d", fqdn, dnsType),
		}, models.SpfResult{}
	}

	// Stuff must be in the answer section
	for _, a := range r.Answer {
		switch txt := a.(type) {
		case *dns.SPF:
		case *dns.TXT:
			txtString := strings.Join(txt.Txt, "")
			if strings.HasPrefix(txtString, "v=spf1") {
				foundSpf = true
				spfTxt = txtString
			}
		}
	}

	if !foundSpf {
		return models.AnalyzerResults{
			Severity: models.ERROR,
			Rule:     models.UNRESOLVEABLE_DOMAIN,
			Message:  fmt.Sprintf("No SPF records found for domain \"%s\" for type %d", fqdn, dnsType),
		}, models.SpfResult{}
	}

	domains = append(domains, fqdn)

	return models.AnalyzerResults{}, parseSpfRecord(client, dnsServer, dnsType, domain, spfTxt, domains, fixErrors)
}

func (c *spfTxtWorker) SetNext(worker models.IDNSWorker) {
	c.next = worker
}
