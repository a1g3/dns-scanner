package parse

import (
	"dnsScanner/models"
	"net"
	"strings"
)

func ip6Parser(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	if !strings.Contains(fragment, "/") {
		fragment = fragment + "/128"
	}
	ipv6Addr, ipv6Net, err := net.ParseCIDR(strings.TrimPrefix(fragment, "ip6:"))
	if err != nil {
		return parseError(raw, fragment, qualifier)
	} else {
		parsedIp := models.Ip6SpfFragment{}
		parsedIp.Raw = raw
		parsedIp.Qualifier = qualifier
		parsedIp.Ip = ipv6Addr
		parsedIp.Cidr = *ipv6Net

		return parsedIp
	}
}
