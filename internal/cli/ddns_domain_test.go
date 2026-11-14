package cli

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestDDNSDirectValidationFollowsChangedAnswers(t *testing.T) {
	for _, address := range []string{"8.8.8.8", "1.1.1.1"} {
		lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host != "node.example.com" && host != "ddns.example.com" {
				t.Fatalf("unexpected lookup %s", host)
			}
			return []net.IPAddr{{IP: net.ParseIP(address)}}, nil
		}
		if err := validateDomainAddress(context.Background(), "direct", "node.example.com", "DDNS.EXAMPLE.COM.", lookup); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDDNSDirectValidationRejectsMismatchAndLookupFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host == "ddns.example.com" {
				if fail {
					return nil, errors.New("DNS unavailable")
				}
				return []net.IPAddr{{IP: net.ParseIP("1.1.1.1")}}, nil
			}
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}
		if err := validateDomainAddress(context.Background(), "direct", "node.example.com", "ddns.example.com", lookup); err == nil {
			t.Fatal("invalid DDNS origin accepted")
		}
	}
}

func TestDDNSCloudflareCertificateDoesNotRequireMatchingEdgeIP(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("DNS-01 compared proxied edge IP")
		return nil, nil
	}
	if err := validateDomainAddress(context.Background(), "cloudflare", "node.example.com", "ddns.example.com", lookup); err != nil {
		t.Fatal(err)
	}
}
