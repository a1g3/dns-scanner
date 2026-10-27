package parse

import (
	"dnsScanner/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseSpfRecord_BareString(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1")

	assert.Equal(t, 1, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)
}

func TestParseSpfRecord_NoEmail(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 -all")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	all := parsedSpf[1].(models.AllSpfFragment)
	assert.Equal(t, "-all", all.Raw)
	assert.Equal(t, "all", all.Contents)
	assert.Equal(t, models.HardFail, all.Qualifier)
}

func TestParseSpfRecord_AllowAll(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 all")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	all := parsedSpf[1].(models.AllSpfFragment)
	assert.Equal(t, "all", all.Raw)
	assert.Equal(t, "all", all.Contents)
	assert.Equal(t, models.Pass, all.Qualifier)
}

func TestParseSpfRecord_AllowIpv4(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 ip4:192.168.0.1")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	ip := parsedSpf[1].(models.Ip4SpfFragment)
	assert.Equal(t, "ip4:192.168.0.1", ip.Raw)
	assert.Equal(t, "192.168.0.1", ip.Ip.String())
	assert.Equal(t, "192.168.0.1", ip.Cidr.IP.String())
	assert.Equal(t, "ffffffff", ip.Cidr.Mask.String())
}

func TestParseSpfRecord_AllowIpv4_WithMask(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 ip4:192.168.0.1/16")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	ip := parsedSpf[1].(models.Ip4SpfFragment)
	assert.Equal(t, "ip4:192.168.0.1/16", ip.Raw)
	assert.Equal(t, "192.168.0.1", ip.Ip.String())
	assert.Equal(t, "192.168.0.0", ip.Cidr.IP.String())
	assert.Equal(t, "ffff0000", ip.Cidr.Mask.String())
}

func TestParseSpfRecord_AllowIpv4_Unparseable(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 ip4:192.168.565.1")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	err := parsedSpf[1].(models.UnparseableSpfFragment)
	assert.Equal(t, "ip4:192.168.565.1", err.Raw)
}

func TestParseSpfRecord_AllowIpv6(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 ip6:fd16:209c:4b53:6481::")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	ip := parsedSpf[1].(models.Ip6SpfFragment)
	assert.Equal(t, "ip6:fd16:209c:4b53:6481::", ip.Raw)
	assert.Equal(t, "fd16:209c:4b53:6481::", ip.Ip.String())
	assert.Equal(t, "fd16:209c:4b53:6481::", ip.Cidr.IP.String())
	assert.Equal(t, "ffffffffffffffffffffffffffffffff", ip.Cidr.Mask.String())
}

func TestParseSpfRecord_AllowIpv6_WithMask(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 ip6:fd16:209c:4b53:6481::/96")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	ip := parsedSpf[1].(models.Ip6SpfFragment)
	assert.Equal(t, "ip6:fd16:209c:4b53:6481::/96", ip.Raw)
	assert.Equal(t, "fd16:209c:4b53:6481::", ip.Ip.String())
	assert.Equal(t, "fd16:209c:4b53:6481::", ip.Cidr.IP.String())
	assert.Equal(t, "ffffffffffffffffffffffff00000000", ip.Cidr.Mask.String())
}

func TestParseSpfRecord_AllowIpv6_Unparseable(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 ip6:fd16:209c:4b53:6481::/543")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	err := parsedSpf[1].(models.UnparseableSpfFragment)
	assert.Equal(t, "ip6:fd16:209c:4b53:6481::/543", err.Raw)
}

func TestParseSpfRecord_Includes(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 include:spf.example.com")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	include := parsedSpf[1].(models.IncludeSpfFragment)
	assert.Equal(t, "include:spf.example.com", include.Raw)
	assert.Equal(t, models.Pass, include.Qualifier)
	assert.Equal(t, "spf.example.com", include.Contents)
}

func TestParseSpfRecord_IncludesWithAll(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 include:spf.protection.outlook.com -all")

	assert.Equal(t, 3, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	include := parsedSpf[1].(models.IncludeSpfFragment)
	assert.Equal(t, "include:spf.protection.outlook.com", include.Raw)
	assert.Equal(t, models.Pass, include.Qualifier)
	assert.Equal(t, "spf.protection.outlook.com", include.Contents)

	all := parsedSpf[2].(models.AllSpfFragment)
	assert.Equal(t, "-all", all.Raw)
	assert.Equal(t, models.HardFail, all.Qualifier)
	assert.Equal(t, "all", all.Contents)
}

func TestParseSpfRecord_BlankA(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 a")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	aMech := parsedSpf[1].(models.ASpfFragment)
	assert.Equal(t, "a", aMech.Raw)
	assert.Equal(t, models.Pass, aMech.Qualifier)
	assert.Equal(t, "", aMech.Contents)
}

func TestParseSpfRecord_AWithDomain(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 a:example.com")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	aMech := parsedSpf[1].(models.ASpfFragment)
	assert.Equal(t, "a:example.com", aMech.Raw)
	assert.Equal(t, models.Pass, aMech.Qualifier)
	assert.Equal(t, "example.com", aMech.Contents)
}

func TestParseSpfRecord_AWithMask(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 a/20")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	aMech := parsedSpf[1].(models.ASpfFragment)
	assert.Equal(t, "a/20", aMech.Raw)
	assert.Equal(t, models.Pass, aMech.Qualifier)
	assert.Equal(t, "/20", aMech.Contents)
}

func TestParseSpfRecord_UnknownModifier(t *testing.T) {
	parsedSpf := ParseSpf("v=spf1 ip5:3234")

	assert.Equal(t, 2, len(parsedSpf))
	assert.Equal(t, "v=spf1", parsedSpf[0].(models.HeaderSpfFragment).Contents)

	err := parsedSpf[1].(models.UnparseableSpfFragment)
	assert.Equal(t, "ip5:3234", err.Raw)
}
