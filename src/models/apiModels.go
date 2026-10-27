package models

import "net"

type DnsApiScanResult struct {
	Domain  string `json:"domain"`
	Version string `json:"version"`

	Caa    CaaScanResult    `json:"caa"`
	Dmarc  DmarcScanResult  `json:"dmarc"`
	Dnskey DnskeyScanResult `json:"dnssec"`
	Mx     MxScanResult     `json:"mx"`
	Ns     NsScanResult     `json:"ns"`
	Spf    []SpfScanResult  `json:"spf"`
	OldSpf []SpfScanResult  `json:"old_spf"`

	Errors []ErrorResult `json:"errors"`
}

type CaaScanResult struct {
	Issue        []string `json:"issue"`
	IssueWild    []string `json:"issue_wild"`
	Iodef        []string `json:"iodef"`
	ContactPhone []string `json:"contact_phone"`
	ContactEmail []string `json:"contact_email"`

	DnsScanResult
}

type DmarcScanResult struct {
	Domain     string               `json:"domain"`
	Validation []ApiAnalyzerResults `json:"validation"`

	Request         *string `json:"p"`
	ADkim           *string `json:"adkim"`
	ASpf            *string `json:"aspf"`
	SRequest        *string `json:"sp"`
	AInterval       int     `json:"ri"`
	Percent         int     `json:"pct"`
	FailureOptions  *string `json:"fo"`
	FormatFragment  *string `json:"rf"`
	ReportAggregate *string `json:"rua"`
	ReportFailure   *string `json:"ruf"`

	DnsScanResult
}

type DnskeyScanResult struct {
	DnsScanResult
}

type MxScanResult struct {
	MailRecords []MxRecordSpfScanResult `json:"mail_records"`

	DnsScanResult
}

type NsScanResult struct {
	DnsScanResult
}

type ASpfScanResult struct {
	Domain string
	Ips    []net.IP
}

type MxSpfScanResult struct {
	Domain    string                  `json:"domain"`
	MxRecords []MxRecordSpfScanResult `json:"records"`
}

type MxRecordSpfScanResult struct {
	Raw        string   `json:"raw"`
	Domain     string   `json:"domain"`
	Preference uint16   `json:"preference"`
	Ips        []net.IP `json:"ips"`
}

type SpfScanResult struct {
	Domain          string               `json:"domain"`
	Validation      []ApiAnalyzerResults `json:"validation"`
	NumberOfLookups int                  `json:"number_of_lookups"`
	DnsScanResult
	Includes  []SpfScanResult   `json:"includes"`
	Redirects []SpfScanResult   `json:"redirects"`
	A         []ASpfScanResult  `json:"a"`
	Exists    []ASpfScanResult  `json:"exists"`
	Mx        []MxSpfScanResult `json:"mx"`
}

type ErrorResult struct {
	WorkerName string `json:"worker"`
	Error      string `json:"error"`
}

type ApiAnalyzerResults struct {
	Severity int    `json:"severity"`
	Rule     int    `json:"rule"`
	Message  string `json:"message"`
}

type DnsScanResult struct {
	RawRecords []string `json:"raw"`
}
