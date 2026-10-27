package main

import (
	"dnsScanner/models"
	"dnsScanner/workers"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func scanDns(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	domain := vars["domain"]

	results := workers.ScanDns(domain)
	data, err := json.Marshal(mapToApiModel(domain, results))

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(data)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func handleRequests() {
	log.Println("STARTING API")
	myRouter := mux.NewRouter().StrictSlash(true)
	// replace http.HandleFunc with myRouter.HandleFunc
	myRouter.HandleFunc("/api/{domain}", scanDns)
	log.Fatal(http.ListenAndServe(":10000", myRouter))
}

func mapToApiModel(domain string, dnsResults []models.DnsWorkerResults) models.DnsApiScanResult {
	result := models.DnsApiScanResult{
		Domain:  domain,
		Version: "1.7cdc283",
		Caa:     models.CaaScanResult{},
		Dmarc:   models.DmarcScanResult{},
		Dnskey:  models.DnskeyScanResult{},
		Mx:      models.MxScanResult{},
		Ns:      models.NsScanResult{},
	}

	for _, a := range dnsResults {
		switch record := a.(type) {
		case models.CaaWorkerResult:
			result.Caa.RawRecords = record.Records
			result.Caa.Issue = record.Issue
			result.Caa.IssueWild = record.IssueWild
			result.Caa.Iodef = record.Iodef
			result.Caa.ContactEmail = record.ContactEmail
			result.Caa.ContactPhone = record.ContactPhone
		case models.NsWorkerResult:
			result.Ns.RawRecords = record.Records
		case models.DnssecWorkerResult:
			result.Dnskey.RawRecords = record.Records
		case models.MxWorkerResult:
			result.Mx.RawRecords = record.Records
			result.Mx.MailRecords = mapMxRecordsToMxSpfScanResult(record.Mx)
		case models.DmarcWorkerResult:
			result.Dmarc.Domain = record.Domain
			result.Dmarc.RawRecords = record.Records
			result.Dmarc.Request = &record.Request
			result.Dmarc.ADkim = &record.ADkim
			result.Dmarc.ASpf = &record.ASpf
			result.Dmarc.SRequest = &record.SRequest
			result.Dmarc.AInterval = record.AInterval
			result.Dmarc.Percent = record.Percent
			result.Dmarc.FailureOptions = &record.FailureOptions
			result.Dmarc.FormatFragment = &record.FormatFragment
			result.Dmarc.ReportAggregate = &record.ReportAggregate
			result.Dmarc.ReportFailure = &record.ReportFailure
			result.Dmarc.Validation = getDmarcValidationResults(record.Validation)
		case models.SpfWorkerResult:
			for _, spfResult := range record.Results {
				result.Spf = append(result.Spf, getSpfResults(spfResult))
			}
		case models.OldSpfWorkerResult:
			for _, spfResult := range record.Results {
				result.OldSpf = append(result.OldSpf, getSpfResults(spfResult))
			}
		case models.DnsErrorResult:
			result.Errors = append(result.Errors, models.ErrorResult{
				WorkerName: record.WorkerName,
				Error:      record.Error,
			})
		default:
			log.Fatalf("Unknown worker result %T!", record)
		}
	}

	fmt.Printf("=== Finished scan for %s ===\n", domain)

	return result
}

func getAResults(results []models.ASpf) []models.ASpfScanResult {
	var apiResults []models.ASpfScanResult

	for _, result := range results {
		apiResults = append(apiResults, models.ASpfScanResult{
			Domain: result.Domain,
			Ips:    result.Ips,
		})
	}

	return apiResults
}

func getSpfResults(result models.SpfResult) models.SpfScanResult {
	res := models.SpfScanResult{
		Validation:      getValidationResults(result.Validation),
		Domain:          result.Domain,
		A:               getAResults(result.ASpf),
		Exists:          getAResults(result.Exists),
		Mx:              getMxResults(result.Mx),
		NumberOfLookups: result.NumberOfLookups,
		DnsScanResult:   models.DnsScanResult{RawRecords: []string{result.Raw}},
	}

	if len(result.Includes) != 0 {
		var scanResults []models.SpfScanResult
		for _, inc := range result.Includes {
			scanResults = append(scanResults, getSpfResults(inc))
		}

		res.Includes = scanResults
	}

	if len(result.Redirects) != 0 {
		var redirectScanResults []models.SpfScanResult
		for _, inc := range result.Redirects {
			redirectScanResults = append(redirectScanResults, getSpfResults(inc))
		}

		res.Redirects = redirectScanResults
	}

	return res
}

func getDmarcValidationResults(analyzerResults []models.DmarcAnalyzerResults) []models.ApiAnalyzerResults {
	var apiAnalyzerResults []models.ApiAnalyzerResults

	for _, result := range analyzerResults {
		apiAnalyzerResults = append(apiAnalyzerResults, models.ApiAnalyzerResults{
			Severity: int(result.Severity),
			Rule:     int(result.Rule),
			Message:  result.Message,
		})
	}

	return apiAnalyzerResults
}

func getValidationResults(analyzerResults []models.AnalyzerResults) []models.ApiAnalyzerResults {
	var apiAnalyzerResults []models.ApiAnalyzerResults

	for _, result := range analyzerResults {
		apiAnalyzerResults = append(apiAnalyzerResults, models.ApiAnalyzerResults{
			Severity: int(result.Severity),
			Rule:     int(result.Rule),
			Message:  result.Message,
		})
	}

	return apiAnalyzerResults
}

func getMxResults(mx []models.MxHelperModel) []models.MxSpfScanResult {
	var mxScanResults []models.MxSpfScanResult

	for _, result := range mx {
		mxScanResults = append(mxScanResults, models.MxSpfScanResult{
			Domain:    result.Domain,
			MxRecords: mapMxRecordsToMxSpfScanResult(result.MxRecords),
		})
	}

	return mxScanResults
}

func mapMxRecordsToMxSpfScanResult(records []models.MxRecord) []models.MxRecordSpfScanResult {
	var mxScanResults []models.MxRecordSpfScanResult

	for _, record := range records {
		mxScanResults = append(mxScanResults, models.MxRecordSpfScanResult{
			Raw:        record.Raw,
			Domain:     record.Domain,
			Preference: record.Preference,
			Ips:        record.Ips,
		})
	}
	return mxScanResults
}

func main() {
	handleRequests()
}
