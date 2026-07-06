package util

import "testing"

func TestValidateExternalURLRejectsUnsafeTargets(t *testing.T) {
	cases := []string{
		"http://127.0.0.1:8080/sub",
		"http://localhost/sub",
		"http://10.0.0.1/sub",
		"http://172.16.0.1/sub",
		"http://192.168.1.1/sub",
		"http://169.254.169.254/latest/meta-data",
		"http://100.100.100.200/latest/meta-data",
		"file:///etc/passwd",
	}
	for _, rawURL := range cases {
		if err := validateExternalURL(mustParseURL(t, rawURL)); err == nil {
			t.Fatalf("expected %s to be rejected", rawURL)
		}
	}
}

func TestValidateExternalURLAllowsPublicHTTPSScheme(t *testing.T) {
	if err := validateExternalURL(mustParseURL(t, "https://93.184.216.34/sub")); err != nil {
		t.Fatalf("expected public HTTPS IP to be allowed: %v", err)
	}
}
