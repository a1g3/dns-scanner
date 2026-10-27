package models

import (
	"net"

	"github.com/miekg/dns"
)

type WorkerInformation struct {
	Hostname  string
	Client    *dns.Client
	DnsServer string
}

type OldSpfWorkerResult struct {
	SpfWorkerResult
}

type ASpf struct {
	Domain string
	Ips    []net.IP

	RecordReturn
}

type SpfResult struct {
	Domain          string
	Raw             string
	NumberOfLookups int
	Includes        []SpfResult
	Redirects       []SpfResult
	Exists          []ASpf
	Mx              []MxHelperModel
	ASpf            []ASpf
	Validation      []AnalyzerResults
}

type DmarcWorkerResult struct {
	Domain     string
	Raw        string
	Validation []DmarcAnalyzerResults

	Request         string
	ADkim           string
	ASpf            string
	SRequest        string
	AInterval       int
	Percent         int
	FailureOptions  string
	FormatFragment  string
	ReportAggregate string
	ReportFailure   string

	DnsResult
}

type SpfWorkerResult struct {
	Results []SpfResult
}

type IDNSWorker interface {
	Execute(information WorkerInformation) []DnsWorkerResults
	SetNext(worker IDNSWorker)
}

type CaaWorkerResult struct {
	Issue        []string
	IssueWild    []string
	Iodef        []string
	ContactEmail []string
	ContactPhone []string
	DnsResult
}

type DnssecWorkerResult struct {
	DnsResult
}

type MxWorkerResult struct {
	Mx []MxRecord

	DnsResult
}

type NsWorkerResult struct {
	DnsResult
}

type DnsErrorResult struct {
	WorkerName string
	Error      string
}

type DnsResult struct {
	Records []string
}

type DnsWorkerResults interface {
}
