package netguard

import (
	"net"
	"testing"
)

func TestIsInternalIP(t *testing.T) {
	internal := []string{
		"127.0.0.1", "::1", "0.0.0.0", "::",
		"10.0.0.1", "172.16.0.5", "192.168.1.10",
		"169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1",
		"100.64.0.1", "100.127.255.255", // CGNAT (RFC 6598)
		"192.0.0.170", "192.0.2.1", // 192.0.0.0/24 + TEST-NET-1 (ditolak eksplisit; IsPrivate Go tidak mencakupnya)
		"198.18.0.1", "198.19.255.255", // benchmarking (RFC 2544)
	}
	for _, s := range internal {
		if !IsInternalIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be internal", s)
		}
	}

	public := []string{"8.8.8.8", "93.184.216.34", "2001:4860:4860::8888", "1.1.1.1"}
	for _, s := range public {
		if IsInternalIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be public", s)
		}
	}

	if !IsInternalIP(nil) {
		t.Error("expected nil IP to be treated as internal")
	}
}

func TestValidatePublicURL(t *testing.T) {
	valid := []string{
		"",
		"https://8.8.8.8/hook",
		"http://93.184.216.34:9000/x",
		"https://[2001:4860:4860::8888]/hook",
	}
	for _, u := range valid {
		if err := ValidatePublicURL(u); err != nil {
			t.Errorf("expected %q valid, got %v", u, err)
		}
	}

	invalid := []string{
		"example.com",
		"ftp://example.com",
		"https://",
		"javascript:alert(1)",
		"http://localhost/hook",
		"http://10.0.0.1:9000/x",
		"http://127.0.0.1/hook",
		"http://192.168.1.10/hook",
		"http://169.254.169.254/latest/meta-data",
		"http://0.0.0.0/hook",
		"http://[::1]/hook",
		"http://100.64.0.1/hook",
		"http://192.0.0.170/hook",
		"http://198.18.0.1/hook",
	}
	for _, u := range invalid {
		if err := ValidatePublicURL(u); err == nil {
			t.Errorf("expected %q invalid (SSRF guard)", u)
		}
	}
}
