package core

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

const (
	ipv6len = 16
)

// var internalIPNet *net.IPNet
var globalIPNet *net.IPNet

// netIPIsPrivate
// https://github.com/6543-forks/go/commit/c73fccc384c699f857abd0a566bbbc1529969fd9
// IsPrivate reports whether ip is a private address, according to
// RFC 1918 (IPv4 addresses) and RFC 4193 (IPv6 addresses).
func netIPIsPrivate(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xf0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return len(ip) == ipv6len && ip[0]&0xfe == 0xfc
}

func findPublicIPByHardwareInfo(interfaceName string) []*net.IPNet {
	interfaces, err := net.InterfaceByName(interfaceName)
	if err != nil {
		panic(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return nil
	}
	addresses, err := interfaces.Addrs()
	if err != nil {
		panic(fmt.Errorf("localAddresses: %+v\n", err.Error()))
		return nil
	}

	var publicIPs = make([]*net.IPNet, 0)
	for _, a := range addresses {
		switch v := a.(type) {
		case *net.IPNet:
			if !netIPIsPrivate(v.IP) && globalIPNet.Contains(v.IP) {
				publicIPs = append(publicIPs, v)
			}
		}
	}
	return publicIPs
}

func sortIPNetByIPs(optionIPs []*net.IPNet, preferIPs []net.IP) {
	var j = 0
	for _, ip := range preferIPs {
		for i, option := range optionIPs {
			if option.IP.Equal(ip) {
				optionIPs[i], optionIPs[j] = optionIPs[j], optionIPs[i]
				j = j + 1
				break
			}
		}
	}
}

var defaultTransport http.RoundTripper = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:          30,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   15 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}
var client = &http.Client{Transport: defaultTransport}

func GetPublicIPs(interfaceName string) []net.IP {
	var publicIPNets = findPublicIPByHardwareInfo(interfaceName)
	resp, err := client.Get("https://api64.ipify.org") //"https://checkip.dyndns.org") // "https://www.trackip.net/ip?json")// // "http://v6.ipv6-test.com/api/myip.php")
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	var publicIpByNetwork = net.ParseIP(string(body))
	sortIPNetByIPs(publicIPNets, []net.IP{publicIpByNetwork})
	var result = make([]net.IP, len(publicIPNets))
	for i, ipNet := range publicIPNets {
		result[i] = ipNet.IP
	}
	return result
}

func init() {
	// _, internalIPNet_, _ := net.ParseCIDR("fe80::/16")
	_, globalIPNet_, _ := net.ParseCIDR("2000::/3")
	// internalIPNet = internalIPNet_
	globalIPNet = globalIPNet_
}
