package analyze

import (
	"dnsScanner/models"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeSpfRecord_ValidHeader(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	assert.Empty(t, results)
}

func TestAnalyzeSpfRecord_NoHeaders(t *testing.T) {
	var fragments []models.ParsedSpfFragment

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, models.NO_HEADER, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "No valid SPF header found!", error.Message)
}

func TestAnalyzeSpfRecord_MultipleHeaders(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, models.MULTIPLE_HEADERS, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "Multiple SPF headers found!", error.Message)
}

func TestAnalyzeSpfRecord_HeaderNotFirst(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	fragments = append(fragments, models.ASpfFragment{})
	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, models.HEADER_NOT_FIRST, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "SPF header must be first!", error.Message)
}

func TestAnalyzeSpfRecord_UnparseableFragment(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, frag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, models.UNKNOWN_MECH, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Unknown fragment \"ip5:thisisatest\"", error.Message)
}

func TestAnalyzeSpfRecord_UnparseableFragmentNoHeader(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	fragments = append(fragments, frag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

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
	var fragments []models.ParsedSpfFragment
	aFrag := models.ASpfFragment{}
	aFrag.Raw = "a:google.com"

	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, aFrag)
	fragments = append(fragments, allFrag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	assert.Empty(t, results)
}

func TestAnalyzeSpfRecord_AllIsNotLastElement(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	aFrag := models.ASpfFragment{}
	aFrag.Raw = "a:google.com"

	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)
	fragments = append(fragments, aFrag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, models.MECH_AFTER_ALL, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms after all will be ignored.", error.Message)
}

func TestAnalyzeSpfRecord_ModifiersAfterAll(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	e1 := models.ExplanationSpfFragment{}
	e1.Raw = "exp=explain._spf.%{d}"
	e1.Domain = "explain._spf.%{d}"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)
	fragments = append(fragments, e1)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	assert.Empty(t, results)
}

func TestAnalyzeSpfRecord_PassAll(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "+all"
	allFrag.Qualifier = models.Pass

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, models.PASS_ALL, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Check the +all to ensure this is intended!", error.Message)
}

func TestAnalyzeSpfRecord_HasPtrRecord(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	allFrag := models.PtrSpfFragment{}
	allFrag.Raw = "ptr"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, allFrag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, models.DEPRECATED_PTR, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The ptr mechanism is deprecated and should not be used!", error.Message)
}

func TestAnalyzeSpfRecord_RedirectAndAll(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "+all"

	redirect := models.RedirectSpfFragment{}
	redirect.Raw = "redirect=google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, redirect)
	fragments = append(fragments, allFrag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

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
	var fragments []models.ParsedSpfFragment

	r1 := models.RedirectSpfFragment{}
	r1.Domain = "google.com"
	r1.Raw = "redirect=google.com"

	e1 := models.ExplanationSpfFragment{}
	e1.Raw = "exp=explain._spf.%{d}"
	e1.Domain = "explain._spf.%{d}"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, r1)
	fragments = append(fragments, e1)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

	assert.Equal(t, 0, len(results))
}

func TestAnalyzeSpfRecord_DuplicateModifiers(t *testing.T) {
	var fragments []models.ParsedSpfFragment

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

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)

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
	var fragments []models.ParsedSpfFragment
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "-all"
	allFrag.Qualifier = models.HardFail

	e1 := models.ExplanationSpfFragment{}
	e1.Raw = "exp=explain._spf.%{d}"
	e1.Domain = "explain._spf.%{d}"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, e1)
	fragments = append(fragments, allFrag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: false,
	}
	results := AnalyzeSpf(&analysisInfo)
	assert.Equal(t, 1, len(results))

	error := results[0]
	assert.Equal(t, models.MECH_AFTER_MODIFIER, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms should not appear after explanation or redirect modifiers.", error.Message)
}

func TestAnalyzeSpfRecord_Fix_UnparseableFragment(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, frag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 2, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.UNKNOWN_MECH, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Unknown fragment \"ip5:thisisatest\"", error.Message)
}

func TestAnalyzeSpfRecord_Fix_UnparseableFragment_Complex(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	include := CreateIncludeFragment()

	var unparseable2 = models.UnparseableSpfFragment{}
	unparseable2.Raw = "ipasdfaasdf!&@*$(*(%_)-23094thisisatest"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, frag)
	fragments = append(fragments, include)
	fragments = append(fragments, unparseable2)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 3, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 include:google.com", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.UNKNOWN_MECH, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Unknown fragment \"ip5:thisisatest\"", error.Message)

	error = results[2]
	assert.Equal(t, models.UNKNOWN_MECH, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Unknown fragment \"ipasdfaasdf!&@*$(*(%_)-23094thisisatest\"", error.Message)
}

func TestAnalyzeSpfRecord_Fix_Ptr(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	var ptr = models.PtrSpfFragment{}
	ptr.Raw = "ptr"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, ptr)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 2, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.DEPRECATED_PTR, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The ptr mechanism is deprecated and should not be used!", error.Message)
}

func TestAnalyzeSpfRecord_Fix_Ptr_Complex(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	var frag = models.UnparseableSpfFragment{}
	frag.Raw = "ip5:thisisatest"

	var ptr = models.PtrSpfFragment{}
	ptr.Raw = "ptr"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, ptr)
	fragments = append(fragments, CreateIncludeFragment())
	fragments = append(fragments, CreateIpv4Fragment())

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 2, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 include:google.com ip4:192.168.1.1", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.DEPRECATED_PTR, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The ptr mechanism is deprecated and should not be used!", error.Message)
}

func TestAnalyzeSpfRecord_Fix_RedirectAndAll(t *testing.T) {
	var fragments []models.ParsedSpfFragment
	allFrag := models.AllSpfFragment{}
	allFrag.Raw = "+all"

	redirect := models.RedirectSpfFragment{}
	redirect.Domain = "google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, redirect)
	fragments = append(fragments, allFrag)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 3, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 redirect=google.com", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.ALL_WITH_REDIRECT, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The all mechanism cannot be present with redirect modifier!", error.Message)

	error = results[2]
	assert.Equal(t, models.MECH_AFTER_MODIFIER, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms should not appear after explanation or redirect modifiers.", error.Message)
}

func TestAnalyzeSpfRecord_Fix_RedirectAndAll_Complex(t *testing.T) {
	var fragments []models.ParsedSpfFragment

	redirect := models.RedirectSpfFragment{}
	redirect.Domain = "google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, redirect)
	fragments = append(fragments, models.AllSpfFragment{})
	fragments = append(fragments, models.AllSpfFragment{})
	fragments = append(fragments, models.AllSpfFragment{})
	fragments = append(fragments, models.AllSpfFragment{})
	fragments = append(fragments, models.AllSpfFragment{})

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 redirect=google.com", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.ALL_WITH_REDIRECT, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The all mechanism cannot be present with redirect modifier!", error.Message)

	error = results[2]
	assert.Equal(t, models.MECH_AFTER_MODIFIER, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms should not appear after explanation or redirect modifiers.", error.Message)
}

func TestAnalyzeSpfRecord_Fix_NoModifiersAfterRedirect(t *testing.T) {
	var fragments []models.ParsedSpfFragment

	redirect := models.RedirectSpfFragment{}
	redirect.Domain = "google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, redirect)
	fragments = append(fragments, CreateIpv4Fragment())

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 2, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 ip4:192.168.1.1 redirect=google.com", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.MECH_AFTER_MODIFIER, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms should not appear after explanation or redirect modifiers.", error.Message)
}

func TestAnalyzeSpfRecord_Fix_NoModifiersAfterRedirect_Complex(t *testing.T) {
	var fragments []models.ParsedSpfFragment

	redirect := models.RedirectSpfFragment{}
	redirect.Domain = "google.com"

	explanation := models.ExplanationSpfFragment{}
	explanation.Domain = "google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, redirect)
	fragments = append(fragments, CreateIpv4Fragment())
	fragments = append(fragments, CreateIncludeFragment())
	fragments = append(fragments, explanation)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 3, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 ip4:192.168.1.1 include:google.com redirect=google.com exp=google.com", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.MECH_AFTER_MODIFIER, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms should not appear after explanation or redirect modifiers.", error.Message)

	error = results[2]
	assert.Equal(t, models.MECH_AFTER_MODIFIER, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms should not appear after explanation or redirect modifiers.", error.Message)
}

func TestAnalyzeSpfRecord_Fix_NoFragmentsAfterAll(t *testing.T) {
	var fragments []models.ParsedSpfFragment

	all := models.AllSpfFragment{}

	explanation := models.ExplanationSpfFragment{}
	explanation.Domain = "google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, all)
	fragments = append(fragments, CreateIpv4Fragment())
	fragments = append(fragments, CreateIncludeFragment())
	fragments = append(fragments, explanation)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 3, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 ip4:192.168.1.1 include:google.com all exp=google.com", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.MECH_AFTER_ALL, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms after all will be ignored.", error.Message)

	error = results[2]
	assert.Equal(t, models.MECH_AFTER_ALL, error.Rule)
	assert.Equal(t, models.WARNING, error.Severity)
	assert.Equal(t, "Mechanisms after all will be ignored.", error.Message)
}

func TestAnalyzeSpfRecord_Fix_NoFragmentsAfterAll_Complex(t *testing.T) {
	var fragments []models.ParsedSpfFragment

	all := models.AllSpfFragment{}

	redirect := models.RedirectSpfFragment{}
	redirect.Domain = "google.com"

	explanation := models.ExplanationSpfFragment{}
	explanation.Domain = "google.com"

	fragments = append(fragments, models.HeaderSpfFragment{Contents: "v=spf1"})
	fragments = append(fragments, all)
	fragments = append(fragments, CreateIpv4Fragment())
	fragments = append(fragments, CreateIncludeFragment())
	fragments = append(fragments, explanation)
	fragments = append(fragments, redirect)

	analysisInfo := models.AnalysisInfo{
		ParsedSpf: fragments,
		FixRecord: true,
	}
	results := AnalyzeSpf(&analysisInfo)

	error := results[0]
	assert.Equal(t, 2, len(results))

	assert.Equal(t, models.FIXED_RECORD, error.Rule)
	assert.Equal(t, models.INFO, error.Severity)
	assert.True(t, error.Fixed)
	assert.Equal(t, "", error.Message)
	assert.Equal(t, "v=spf1 ip4:192.168.1.1 include:google.com exp=google.com redirect=google.com", error.FixedRecord)

	error = results[1]
	assert.Equal(t, models.ALL_WITH_REDIRECT, error.Rule)
	assert.Equal(t, models.ERROR, error.Severity)
	assert.Equal(t, "The all mechanism cannot be present with redirect modifier!", error.Message)
}

func CreateIncludeFragment() models.IncludeSpfFragment {
	var include = models.IncludeSpfFragment{}
	include.Qualifier = models.Pass
	include.Contents = "google.com"
	include.ContainsMacros = false
	return include
}

func CreateIpv4Fragment() models.Ip4SpfFragment {
	var ipv4 = models.Ip4SpfFragment{}
	ipv4.Qualifier = models.Pass
	ipv4.Ip = net.ParseIP("192.168.1.1")
	ipv4.Raw = "ip4:192.168.1.1"
	return ipv4
}
