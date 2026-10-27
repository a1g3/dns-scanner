package analyze

import (
	"dnsScanner/models"
	"fmt"
)

type ip4Position struct {
	index int
	value models.Ip4SpfFragment
}

type ip6Position struct {
	index int
	value models.Ip6SpfFragment
}

type ipLengthAnalyzer struct {
	next models.ISPFAnalyzer
}

func (c *ipLengthAnalyzer) Execute(parsedSpf []interface{}) []models.AnalyzerResults {
	var errors []models.AnalyzerResults
	var ip4mechanisms []ip4Position
	var ip6mechanisms []ip6Position

	for i, a := range parsedSpf {
		switch fragment := a.(type) {
		case models.Ip4SpfFragment:
			ip4mechanisms = append(ip4mechanisms, ip4Position{
				index: i,
				value: fragment,
			})
		case models.Ip6SpfFragment:
			ip6mechanisms = append(ip6mechanisms, ip6Position{
				index: i,
				value: fragment,
			})
		}
	}

	for _, ip4 := range ip4mechanisms {
		isize, _ := ip4.value.Cidr.Mask.Size()
		if isize < 16 {
			errors = append(errors, models.AnalyzerResults{
				Severity: models.WARNING,
				Rule:     models.BIG_IP_RANGE,
				Message:  fmt.Sprintf("The CIDR \"%s\" is very large!", ip4.value.Raw),
			})
		}
	}

	for _, ip6 := range ip6mechanisms {
		isize, _ := ip6.value.Cidr.Mask.Size()
		if isize < 64 {
			errors = append(errors, models.AnalyzerResults{
				Severity: models.WARNING,
				Rule:     models.BIG_IP_RANGE,
				Message:  fmt.Sprintf("The CIDR \"%s\" is very large!", ip6.value.Raw),
			})
		}
	}

	results := append(c.next.Execute(parsedSpf), errors...)

	return results
}

func (c *ipLengthAnalyzer) SetNext(worker models.ISPFAnalyzer) {
	c.next = worker
}
