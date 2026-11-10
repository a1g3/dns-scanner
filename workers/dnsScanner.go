package workers

import (
	"dnsScanner/models"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func ScanDns(domain string) []models.DnsWorkerResults {
	c := new(dns.Client)
	c.Net = "tcp"

	base := &baseWorker{}

	caa := &caaWorker{}
	caa.SetNext(base)

	mx := &mxWorker{}
	mx.SetNext(caa)

	spfOld := &spfOldWorker{}
	spfOld.SetNext(mx)

	spfNew := &spfTxtWorker{}
	spfNew.SetNext(spfOld)

	dmarc := &dmarcWorker{}
	dmarc.SetNext(spfNew)

	dnskey := &dnskeyWorker{}
	dnskey.SetNext(dmarc)

	ns := &nsWorker{}
	ns.SetNext(dnskey)

	fmt.Printf("=== Starting scan for %s ===\n", domain)

	host := models.WorkerInformation{
		Hostname:  dns.Fqdn(domain),
		Client:    c,
		DnsServer: net.JoinHostPort(ResolverConfig.Servers[0], ResolverConfig.Port),
	}

	return ns.execute(host)
}
