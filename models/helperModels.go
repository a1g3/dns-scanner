package models

import "net"

type ARecord struct {
	Domain string
	Ips    []net.IP

	RecordReturn
}

type MxHelperModel struct {
	Domain          string
	MxRecords       []MxRecord
	NumberOfLookups int

	RecordReturn
}

type MxRecord struct {
	Raw        string
	Domain     string
	Preference uint16
	Error      []AnalyzerResults

	Ips []net.IP
}
