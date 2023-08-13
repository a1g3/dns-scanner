package workers

import (
	"dnsScanner/models"
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
)

func ScanDns(domain string) []models.DnsWorkerResults {
	config, _ := dns.ClientConfigFromFile(os.Getenv("DNSSCAN_RESOLV_PATH"))
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
		DnsServer: net.JoinHostPort(config.Servers[0], config.Port),
	}

	return ns.execute(host)
}
