package workers

import "dnsScanner/models"

type baseWorker struct {
}

func (c *baseWorker) Execute(_ models.WorkerInformation) []models.DnsWorkerResults {
	return []models.DnsWorkerResults{}
}

func (c *baseWorker) SetNext(_ models.IDNSWorker) {
}
