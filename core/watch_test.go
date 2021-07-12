package core

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func TestGenerateIPV6MasterFile(t *testing.T) {
	var b = bytes.NewBuffer(nil)
	soa := "c.a.b"
	mappingDomain := "d.a.b"
	dnsDomain := "e.a.b"
	privateEscape := "; not local, escaped: "
	serial := int64(0x123)
	ips := []string{"dead::0def::1", "dead::0def::2"}
	err := GenerateIPV6MasterFile(b, &IFv6DNSMasterFileTemplateArgs{
		SOA:           soa,
		MappingDomain: mappingDomain,
		DNSDomain:     dnsDomain,
		PrivateEscape: privateEscape,
		Serial:        serial,
		IPs:           ips,
	})
	if err != nil {
		panic(err)
	}
	out := b.String()
	expectingStrings := []string{
		soa,
		mappingDomain,
		dnsDomain,
		privateEscape,
		strconv.Itoa(int(serial)),
	}
	for _, expected := range append(expectingStrings, ips...) {
		if strings.Index(out, expected) < 0 {
			t.Fatalf("invalid template rendering")
		}
	}
}
