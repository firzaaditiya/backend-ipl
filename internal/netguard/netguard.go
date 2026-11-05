// Package netguard berisi pemeriksaan alamat jaringan untuk mencegah
// Server-Side Request Forgery (SSRF): sebuah URL hanya boleh dipakai sebagai
// tujuan webhook bila host-nya benar-benar publik, baik saat URL disimpan
// maupun saat koneksi dibuat (validasi ulang per-request menutup celah
// redirect dan DNS rebinding setelah penyimpanan).
package netguard

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Jaringan yang tidak pernah dianggap publik. Rentang ini ditolak eksplisit
// sebagai jaring pengaman, di samping hasil IsPrivate / IsLoopback /
// IsLinkLocal bawaan Go, agar penolakan tidak bergantung pada satu definisi
// bawaan saja: CGNAT (100.64.0.0/10, RFC 6598), 192.0.0.0/24 (RFC 6890,
// termasuk 192.0.0.170/171), rentang benchmarking (198.18.0.0/15, RFC 2544),
// tiga rentang dokumentasi TEST-NET (RFC 5737) yang tidak pernah dapat
// dirutekan publik, dan rentang reserved 240.0.0.0/4 (RFC 1112, termasuk
// 255.255.255.255) yang juga tidak dicakup IsPrivate Go.
var nonPublicNetworks = []net.IPNet{
	{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)},
	{IP: net.ParseIP("192.0.0.0"), Mask: net.CIDRMask(24, 32)},
	{IP: net.ParseIP("192.0.2.0"), Mask: net.CIDRMask(24, 32)},
	{IP: net.ParseIP("198.18.0.0"), Mask: net.CIDRMask(15, 32)},
	{IP: net.ParseIP("198.51.100.0"), Mask: net.CIDRMask(24, 32)},
	{IP: net.ParseIP("203.0.113.0"), Mask: net.CIDRMask(24, 32)},
	{IP: net.ParseIP("240.0.0.0"), Mask: net.CIDRMask(4, 32)},
}

// IsInternalIP melaporkan apakah sebuah alamat IP tidak boleh menjadi tujuan
// koneksi keluar: loopback, privat (RFC 1918), unspecified, link-local,
// multicast, CGNAT, rentang benchmarking, dan rentang dokumentasi TEST-NET.
func IsInternalIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() {
		return true
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidatePublicURL memastikan URL memakai skema http/https dan host-nya
// tidak mengarah ke jaringan internal. Hostname di-resolve dan seluruh
// hasil A/AAAA diperiksa; satu saja hasil internal berarti ditolak. Fungsi
// ini dipakai saat URL disimpan DAN sesaat sebelum pengiriman, karena DNS
// dapat berubah (rebinding) di antara kedua momen itu.
func ValidatePublicURL(raw string) error {
	if raw == "" {
		return nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("URL must be a valid http:// or https:// URL")
	}

	host := parsed.Hostname()
	if host == "" {
		return errors.New("URL must include a host")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return errors.New("host must not be localhost")
	}

	if ip := net.ParseIP(host); ip != nil {
		if IsInternalIP(ip) {
			return errors.New("host must be a public address")
		}
		return nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %q", host)
	}
	if len(ips) == 0 {
		return fmt.Errorf("host %q has no address", host)
	}
	for _, ip := range ips {
		if IsInternalIP(ip) {
			return errors.New("host resolves to a non-public address")
		}
	}
	return nil
}
