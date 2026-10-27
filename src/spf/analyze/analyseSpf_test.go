package analyze

import (
	"dnsScanner/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeSpfRecord_ValidHeader(t *testing.T) {
	var fragments []interface{}
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})

	results := AnalyzeSpf(fragments)

	assert.Empty(t, results)
}

func TestAnalyzeSpfRecord_NoHeaders(t *testing.T) {
	var fragments []interface{}

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.NO_HEADER, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "No valid SPF header found!", error.Message)
}

func TestAnalyzeSpfRecord_MultipleHeaders(t *testing.T) {
	var fragments []interface{}
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.MULTIPLE_HEADERS, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "Multiple SPF headers found!", error.Message)
}

func TestAnalyzeSpfRecord_HeaderNotFirst(t *testing.T) {
	var fragments []interface{}
	fragments = append(fragments, models.ASpfFragment{})
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.HEADER_NOT_FIRST, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "SPF header must be first!", error.Message)
}

func TestAnalyzeSpfRecord_UnparseableFragment(t *testing.T) {
	var fragments []interface{}
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, frag)

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.UNKNOWN_MECH, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Unknown fragment \"ip5:thisisatest\"", error.Message)
}

func TestAnalyzeSpfRecord_UnparseableFragmentNoHeader(t *testing.T) {
	var fragments []interface{}
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	fragments = append(fragments, frag)

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.NO_HEADER, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "No valid SPF header found!", error.Message)

	error = results[1]
	assert.Equal(t, models.UNKNOWN_MECH, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Unknown fragment \"ip5:thisisatest\"", error.Message)
}

func TestAnalyzeSpfRecord_AllIsLastElement(t *testing.T) {
	var fragments []interface{}
	aFrag := models.ASpfFragment{}
	aFrag.Raw = "a:google.com"

	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, aFrag)
	fragments = append(fragments, allFrag)

	results := AnalyzeSpf(fragments)

	assert.Empty(t, results)
}

func TestAnalyzeSpfRecord_AllIsNotLastElement(t *testing.T) {
	var fragments []interface{}
	aFrag := models.ASpfFragment{}
	aFrag.Raw = "a:google.com"

	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)
	fragments = append(fragments, aFrag)

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.MECH_AFTER_ALL, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms after all will be ignored.", error.Message)
}

func TestAnalyzeSpfRecord_ModifiersAfterAll(t *testing.T) {
	var fragments []interface{}
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	e1 := models.ExplanationSpfFragment{}
	e1.Raw = "exp=explain._spf.%{d}"
	e1.Domain = "explain._spf.%{d}"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)
	fragments = append(fragments, e1)

	results := AnalyzeSpf(fragments)

	assert.Empty(t, results)
}

func TestAnalyzeSpfRecord_PassAll(t *testing.T) {
	var fragments []interface{}
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "+all"
	allFrag.Qualifier = models.Pass

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.PASS_ALL, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Check the +all to ensure this is intended!", error.Message)
}

func TestAnalyzeSpfRecord_HasPtrRecord(t *testing.T) {
	var fragments []interface{}
	allFrag := models.PtrSpfFragment{}
	allFrag.Raw = "ptr"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.DEPRECATED_PTR, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The ptr mechanism is deprecated and should not be used!", error.Message)
}

func TestAnalyzeSpfRecord_RedirectAndAll(t *testing.T) {
	var fragments []interface{}
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "+all"

	redirect := models.RedirectSpfFragment{}
	redirect.Raw = "redirect=google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, redirect)
	fragments = append(fragments, allFrag)

	results := AnalyzeSpf(fragments)

	error := results[0]
	assert.Equal(t, models.ALL_WITH_REDIRECT, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The all mechanism cannot be present with redirect modifier!", error.Message)
}

/*func TestAnalyzeSpfRecord_IpLongerThanHalf(t *testing.T) {
	var fragments []interface{}

	ip := models.Ip4SpfFragment{}
	ipaddr, cidr, _ := net.ParseCIDR("192.168.1.1/24")
	ip.Ip = ipaddr
	ip.Cidr = *cidr
	ip.Raw = "ip4:192.168.1.1/24"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, ip)

	results := AnalyzeSpf(fragments)

	assert.Equal(t, 0, len(results))
}

func TestAnalyzeSpfRecord_Ip4ShorterThanHalf(t *testing.T) {
	var fragments []interface{}

	ip := models.Ip4SpfFragment{}
	ipaddr, cidr, _ := net.ParseCIDR("192.168.1.1/11")
	ip.Ip = ipaddr
	ip.Cidr = *cidr
	ip.Raw = "ip4:192.168.1.1/11"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, ip)

	results := AnalyzeSpf(fragments)

	assert.Equal(t, 1, len(results))

	error := results[0]
	assert.Equal(t, models.BIG_IP_RANGE, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "The CIDR \"ip4:192.168.1.1/11\" is very large!", error.Message)
}

func TestAnalyzeSpfRecord_Ip6ShorterThanHalf(t *testing.T) {
	var fragments []interface{}

	ip := models.Ip6SpfFragment{}
	ipaddr, cidr, _ := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/46")
	ip.Ip = ipaddr
	ip.Cidr = *cidr
	ip.Raw = "ip6:2001:0db8:85a3:0000:0000:8a2e:0370:7334/46"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, ip)

	results := AnalyzeSpf(fragments)

	assert.Equal(t, 1, len(results))

	error := results[0]
	assert.Equal(t, models.BIG_IP_RANGE, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "The CIDR \"ip6:2001:0db8:85a3:0000:0000:8a2e:0370:7334/46\" is very large!", error.Message)
}

func TestAnalyzeSpfRecord_Ip6LongerThanHalf(t *testing.T) {
	var fragments []interface{}

	ip := models.Ip6SpfFragment{}
	ipaddr, cidr, _ := net.ParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/89")
	ip.Ip = ipaddr
	ip.Cidr = *cidr
	ip.Raw = "ip6:2001:0db8:85a3:0000:0000:8a2e:0370:7334/89"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, ip)

	results := AnalyzeSpf(fragments)

	assert.Equal(t, 0, len(results))
}*/

func TestAnalyzeSpfRecord_NoDuplicateModifiers(t *testing.T) {
	var fragments []interface{}

	r1 := models.RedirectSpfFragment{}
	r1.Domain = "google.com"
	r1.Raw = "redirect=google.com"

	e1 := models.ExplanationSpfFragment{}
	e1.Raw = "exp=explain._spf.%{d}"
	e1.Domain = "explain._spf.%{d}"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, r1)
	fragments = append(fragments, e1)

	results := AnalyzeSpf(fragments)

	assert.Equal(t, 0, len(results))
}

func TestAnalyzeSpfRecord_DuplicateModifiers(t *testing.T) {
	var fragments []interface{}

	r1 := models.RedirectSpfFragment{}
	r1.Domain = "google.com"
	r1.Raw = "redirect=google.com"

	r2 := models.RedirectSpfFragment{}
	r2.Domain = "amazon.com"
	r2.Raw = "redirect=amazon.com"

	e1 := models.ExplanationSpfFragment{}
	e1.Raw = "exp=explain._spf.%{d}"
	e1.Domain = "explain._spf.%{d}"

	e2 := models.ExplanationSpfFragment{}
	e2.Raw = "exp=explain._spf.%{d}"
	e2.Domain = "explain._spf.%{d}"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, r1)
	fragments = append(fragments, r2)
	fragments = append(fragments, e1)
	fragments = append(fragments, e2)

	results := AnalyzeSpf(fragments)

	assert.Equal(t, 2, len(results))

	error := results[0]
	assert.Equal(t, models.DUPLICATE_MODIFIER, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "Only one redirect modifier can appear in a SPF record!", error.Message)

	error = results[1]
	assert.Equal(t, models.DUPLICATE_MODIFIER, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "Only one explanation modifier can appear in a SPF record!", error.Message)
}

func TestAnalyzeSpfRecord_MechanismsAfterModifiers(t *testing.T) {
	var fragments []interface{}
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	e1 := models.ExplanationSpfFragment{}
	e1.Raw = "exp=explain._spf.%{d}"
	e1.Domain = "explain._spf.%{d}"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, e1)
	fragments = append(fragments, allFrag)

	results := AnalyzeSpf(fragments)

	assert.Equal(t, 1, len(results))

	error := results[0]
	assert.Equal(t, models.MECH_AFTER_MODIFIER, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms should not appear after explanation or redirect modifiers.", error.Message)
}
