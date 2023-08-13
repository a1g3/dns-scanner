package parse

import (
	"dnsScanner/models"
	"net"
	"strings"
)

func ip4Parser(raw string, fragment string, qualifier models.Qualifier) models.ParsedSpfFragment {
	if !strings.Contains(fragment, "/") {
		fragment = fragment + "/32"
	}
	ipv4Addr, ipv4Net, err := net.ParseCIDR(strings.TrimPrefix(fragment, "ip4:"))
	if err != nil {
		return parseError(raw, fragment, qualifier)
	} else {
		parsedIp := models.Ip4SpfFragment{}
		parsedIp.Raw = raw
		parsedIp.Qualifier = qualifier
		parsedIp.Ip = ipv4Addr
		parsedIp.Cidr = *ipv4Net

		return parsedIp
	}
}
