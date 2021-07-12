package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"html/template"
	"io"
	"net"
	"os"
	"strings"
)

var log = clog.NewWithPlugin("ifv6_local_core")

type InterfaceIPV6Watcher struct {
	InterfaceName string
	MappingDomain string
	DNSFileDir    string
	PrivateFile   string
	PublicFile    string

	SOA           string
	DNSDomain     string
	PrivateEscape string

	CalcDomains bool
	lastIPs     []net.IP
}

type IFv6DNSMasterFileTemplateArgs struct {
	SOA           string
	MappingDomain string
	DNSDomain     string
	PrivateEscape string
	Serial        int64
	IPs           []string
}

var ifv6DNSMasterFileTemplate *template.Template

func init() {
	var err error
	ifv6DNSMasterFileTemplate, err = template.New("ifv6DNSMasterFileTemplate").Parse(`$TTL    30
@ IN SOA   {{.SOA}} (
  {{.Serial}} ; SERIAL
  7200     ; REFRESH
  600      ; RETRY
  3600000  ; EXPIRE
  60)      ; MINIMUM
@ IN NS {{.DNSDomain}}
{{.DNSDomain}} IN A 127.0.0.1; dns nameserver
{{.PrivateEscape}} {{.MappingDomain}}. IN A 127.0.0.1; local mapping
{{- range $i, $ip := .IPs}}
{{$.MappingDomain}}. IN AAAA {{$ip}}; remote mapping
{{- end}}`)
	if err != nil {
		panic(err)
	}
}

func GenerateIPV6MasterFile(w io.Writer, args *IFv6DNSMasterFileTemplateArgs) error {
	return ifv6DNSMasterFileTemplate.Execute(w, args)
}

func (watcher *InterfaceIPV6Watcher) doCalcDomains() {
	userWantDomain := watcher.MappingDomain
	tw := strings.SplitN(userWantDomain, ".", 2)
	if len(tw) < 1 {
		log.Warningf("interface %q mapping bad domain %s", watcher.InterfaceName, watcher.MappingDomain)
		return
	}

	root := tw[1]
	watcher.SOA = fmt.Sprintf("%s. devops.%s.", root, root)
	watcher.DNSDomain = fmt.Sprintf("dns.%s.", root)
	watcher.CalcDomains = true
}

// Watch the net interface
// todo: Watch once if defined multiple times
func (watcher *InterfaceIPV6Watcher) Watch(serial int64) int64 {
	var ips = GetPublicIPs("enp7s0")
	watcher.lastIPs = ips
	if len(watcher.lastIPs) == 0 {
		log.Warningf("interface %q has no ipv6 address", watcher.InterfaceName)
		return serial
	}

	hash := sha256.New()
	for _, ip := range ips {
		hash.Write(ip)
	}
	sum := hash.Sum(nil)
	// safe?
	newSerialU := binary.BigEndian.Uint64(sum[0:8]) ^ binary.BigEndian.Uint64(sum[8:16]) ^
		binary.BigEndian.Uint64(sum[16:24]) ^ binary.BigEndian.Uint64(sum[24:32])
	newSerial := int64((newSerialU >> 32) & (newSerialU & 0xffffffff))
	if newSerial == serial {
		return serial
	}
	log.Infof("interface %q ip changed, new serial %v, primary ip %s", watcher.InterfaceName, newSerial, watcher.lastIPs[0].String())
	if !watcher.CalcDomains {
		watcher.doCalcDomains()
		if !watcher.CalcDomains {
			return serial
		}
	}
	if len(watcher.PrivateEscape) == 0 {
		watcher.PrivateEscape = "; not local, escaped: "
	}

	var stringIPs = make([]string, len(ips))
	for i, ip := range ips {
		stringIPs[i] = ip.String()
	}
	args := &IFv6DNSMasterFileTemplateArgs{
		SOA:           watcher.SOA,
		MappingDomain: watcher.MappingDomain,
		DNSDomain:     watcher.DNSDomain,
		PrivateEscape: watcher.PrivateEscape,
		Serial:        newSerial,
		IPs:           stringIPs,
	}
	b := bytes.NewBuffer(make([]byte, 0, 100))
	err := GenerateIPV6MasterFile(b, args)
	if err != nil {
		log.Errorf("could not render public master file: %s", err.Error())
		return serial
	}
	err = os.WriteFile(watcher.PublicFile, b.Bytes(), os.FileMode(0644))
	if err != nil {
		log.Errorf("could not write file: %s", err.Error())
		return serial
	}
	b.Reset()
	args.PrivateEscape = ""
	err = GenerateIPV6MasterFile(b, args)
	if err != nil {
		log.Errorf("could not render private master file: %s", err.Error())
		return serial
	}
	err = os.WriteFile(watcher.PrivateFile, b.Bytes(), os.FileMode(0644))
	if err != nil {
		log.Errorf("could not write file: %s", err.Error())
		return serial
	}
	return newSerial
}
