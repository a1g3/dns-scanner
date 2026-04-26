package workers

import (
	"dnsScanner/models"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestAnalyzeSpfRecord_ValidHeader(t *testing.T) {
	resolvconf := "nameserver 8.8.8.8"
	reader := strings.NewReader(resolvconf)
	config, _ := dns.ClientConfigFromReader(reader)
	c := new(dns.Client)
	c.Net = "tcp"

	result := parseSpfRecord(c, net.JoinHostPort(config.Servers[0], config.Port), dns.TypeTXT, "alexgebhard.com", "v=spf1 a:thisdoesnotexist.alexgebhard.com", []string{"alexgebhard.com"}, true)

	assert.Equal(t, "alexgebhard.com", result.Domain)
	assert.Equal(t, 1, result.NumberOfLookups)
	assert.Equal(t, 2, len(result.Validation))

	val_result := result.Validation[0]
	assert.Equal(t, models.INFO, val_result.Severity)
	assert.Equal(t, "v=spf1", val_result.FixedRecord)
	assert.Equal(t, models.FIXED_RECORD, val_result.Rule)

	val_result = result.Validation[1]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.UNRESOLVEABLE_DOMAIN, val_result.Rule)
	assert.Equal(t, "A record for domain \"thisdoesnotexist.alexgebhard.com.\" is not resolved", val_result.Message)
}

func TestAnalyzeSpfRecord_UnresolveableDomain_Complex(t *testing.T) {
	resolvconf := "nameserver 8.8.8.8"
	reader := strings.NewReader(resolvconf)
	config, _ := dns.ClientConfigFromReader(reader)
	c := new(dns.Client)
	c.Net = "tcp"

	result := parseSpfRecord(c, net.JoinHostPort(config.Servers[0], config.Port), dns.TypeTXT, "alexgebhard.com", "v=spf1 a:thisdoesnotexist.alexgebhard.com a a:google.com a:thisdoesnotexist2.alexgebhard.com", []string{"alexgebhard.com"}, true)

	assert.Equal(t, "alexgebhard.com", result.Domain)
	assert.Equal(t, 4, result.NumberOfLookups)
	assert.Equal(t, 3, len(result.Validation))

	val_result := result.Validation[0]
	assert.Equal(t, models.INFO, val_result.Severity)
	assert.Equal(t, "v=spf1 a a:google.com", val_result.FixedRecord)
	assert.Equal(t, models.FIXED_RECORD, val_result.Rule)

	val_result = result.Validation[1]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.UNRESOLVEABLE_DOMAIN, val_result.Rule)
	assert.Equal(t, "A record for domain \"thisdoesnotexist.alexgebhard.com.\" is not resolved", val_result.Message)

	val_result = result.Validation[2]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.UNRESOLVEABLE_DOMAIN, val_result.Rule)
	assert.Equal(t, "A record for domain \"thisdoesnotexist2.alexgebhard.com.\" is not resolved", val_result.Message)
}

func TestAnalyzeSpfRecord_UnresolveableDomain_Complex_NoFix(t *testing.T) {
	resolvconf := "nameserver 8.8.8.8"
	reader := strings.NewReader(resolvconf)
	config, _ := dns.ClientConfigFromReader(reader)
	c := new(dns.Client)
	c.Net = "tcp"

	result := parseSpfRecord(c, net.JoinHostPort(config.Servers[0], config.Port), dns.TypeTXT, "alexgebhard.com", "v=spf1 a:thisdoesnotexist.alexgebhard.com a a:google.com a:thisdoesnotexist2.alexgebhard.com", []string{"alexgebhard.com"}, false)

	assert.Equal(t, "alexgebhard.com", result.Domain)
	assert.Equal(t, 4, result.NumberOfLookups)
	assert.Equal(t, 2, len(result.Validation))

	val_result := result.Validation[0]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.UNRESOLVEABLE_DOMAIN, val_result.Rule)
	assert.Equal(t, "A record for domain \"thisdoesnotexist.alexgebhard.com.\" is not resolved", val_result.Message)

	val_result = result.Validation[1]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.UNRESOLVEABLE_DOMAIN, val_result.Rule)
	assert.Equal(t, "A record for domain \"thisdoesnotexist2.alexgebhard.com.\" is not resolved", val_result.Message)
}

func TestAnalyzeSpfRecord_UnresolveableDomain_Mx_Fix(t *testing.T) {
	resolvconf := "nameserver 8.8.8.8"
	reader := strings.NewReader(resolvconf)
	config, _ := dns.ClientConfigFromReader(reader)
	c := new(dns.Client)
	c.Net = "tcp"

	result := parseSpfRecord(c, net.JoinHostPort(config.Servers[0], config.Port), dns.TypeTXT, "alexgebhard.com", "v=spf1 mx:thisdoesnotexist.alexgebhard.com mx:google.com", []string{"alexgebhard.com"}, true)

	assert.Equal(t, "alexgebhard.com", result.Domain)
	assert.Equal(t, 2, result.NumberOfLookups)
	assert.Equal(t, 2, len(result.Validation))

	val_result := result.Validation[0]
	assert.Equal(t, models.INFO, val_result.Severity)
	assert.Equal(t, "v=spf1 mx:google.com", val_result.FixedRecord)
	assert.Equal(t, models.FIXED_RECORD, val_result.Rule)

	val_result = result.Validation[1]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.UNRESOLVEABLE_DOMAIN, val_result.Rule)
	assert.Equal(t, "Cannot resolve MX record for domain \"thisdoesnotexist.alexgebhard.com.\"", val_result.Message)
}

func TestAnalyzeSpfRecord_Include_Circular_Domain(t *testing.T) {
	resolvconf := "nameserver 8.8.8.8"
	reader := strings.NewReader(resolvconf)
	config, _ := dns.ClientConfigFromReader(reader)
	c := new(dns.Client)
	c.Net = "tcp"

	result := parseSpfRecord(c, net.JoinHostPort(config.Servers[0], config.Port), dns.TypeTXT, "alexgebhard.com", "v=spf1 include:alexgebhard.com", []string{"alexgebhard.com."}, false)

	assert.Equal(t, "alexgebhard.com", result.Domain)
	assert.Equal(t, 1, result.NumberOfLookups)
	assert.Equal(t, 1, len(result.Validation))

	val_result := result.Validation[0]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.CIRCULAR_REFERENCE, val_result.Rule)
	assert.Equal(t, "Circular reference detected with domain alexgebhard.com", val_result.Message)
}

func TestAnalyzeSpfRecord_Include_Unresolveable_Domain(t *testing.T) {
	resolvconf := "nameserver 8.8.8.8"
	reader := strings.NewReader(resolvconf)
	config, _ := dns.ClientConfigFromReader(reader)
	c := new(dns.Client)
	c.Net = "tcp"

	result := parseSpfRecord(c, net.JoinHostPort(config.Servers[0], config.Port), dns.TypeTXT, "alexgebhard.com", "v=spf1 include:thisdoesnotexist.alexgebhard.com", []string{"alexgebhard.com."}, false)

	assert.Equal(t, "alexgebhard.com", result.Domain)
	assert.Equal(t, 1, result.NumberOfLookups)
	assert.Equal(t, 1, len(result.Validation))

	val_result := result.Validation[0]
	assert.Equal(t, models.ERROR, val_result.Severity)
	assert.Equal(t, models.UNRESOLVEABLE_DOMAIN, val_result.Rule)
	assert.Equal(t, "No SPF records found for domain \"thisdoesnotexist.alexgebhard.com.\" for type 16", val_result.Message)
	assert.Equal(t, 0, len(result.Includes))
}
