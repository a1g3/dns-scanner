package parse

import (
	"dnsScanner/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDmarcRecord_EmptyString(t *testing.T) {
	parsedSpf, _ := ParseDmarc("")

	assert.Nil(t, parsedSpf)
}

func TestParseDmarcRecord_BareString(t *testing.T) {
	parsedSpf, _ := ParseDmarc("v=DMARC1;")

	assert.Equal(t, "", parsedSpf.Header.Contents)
	assert.Nil(t, parsedSpf.Frag)
	assert.Nil(t, parsedSpf.Request)
}

func TestParseDmarcRecord_Policy_None(t *testing.T) {
	parsedSpf, _ := ParseDmarc("v=DMARC1;p=none")

	assert.Equal(t, "", parsedSpf.Header.Contents)
	assert.Nil(t, parsedSpf.Frag)
	assert.NotNil(t, parsedSpf.Request)
	assert.Equal(t, "none", parsedSpf.Request.Policy)
}

func TestParseDmarcRecord_Policy_Quarantine(t *testing.T) {
	parsedSpf, _ := ParseDmarc("v=DMARC1;p=quarantine")

	assert.Equal(t, "", parsedSpf.Header.Contents)
	assert.Nil(t, parsedSpf.Frag)
	assert.NotNil(t, parsedSpf.Request)
	assert.Equal(t, "quarantine", parsedSpf.Request.Policy)
}

func TestParseDmarcRecord_Policy_Reject(t *testing.T) {
	parsedSpf, _ := ParseDmarc("v=DMARC1;p=reject")

	assert.Equal(t, "", parsedSpf.Header.Contents)
	assert.Nil(t, parsedSpf.Frag)
	assert.NotNil(t, parsedSpf.Request)
	assert.Equal(t, "reject", parsedSpf.Request.Policy)
}

func TestParseDmarcRecord_SubdomainPolicy_Reject(t *testing.T) {
	parsedSpf, _ := ParseDmarc("v=DMARC1;sp=reject")

	assert.Equal(t, "", parsedSpf.Header.Contents)
	assert.NotNil(t, parsedSpf.Frag)
	assert.Nil(t, parsedSpf.Request)

	srequest := (*parsedSpf.Frag).(models.SrequestFragment)
	assert.IsType(t, models.SrequestFragment{}, srequest)
	assert.Equal(t, "reject", srequest.Value)
	assert.Nil(t, srequest.Next)
}
