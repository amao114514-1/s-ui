package util

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alireza0/s-ui/util/common"
)

const defaultExternalFetchLimit int64 = 5 << 20

func FetchExternalURL(rawURL string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = defaultExternalFetchLimit
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if err := validateExternalURL(parsed); err != nil {
		return "", err
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ip, err := resolveAllowedIP(ctx, host)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return common.NewError("too many redirects")
			}
			return validateExternalURL(req.URL)
		},
	}

	response, err := client.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", common.NewErrorf("unexpected status: %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if int64(len(body)) > maxBytes {
		return "", common.NewError("response body too large")
	}
	return string(body), nil
}

func DialAllowedTCP(ctx context.Context, host string, port string, timeout time.Duration) (net.Conn, error) {
	if host == "" {
		return nil, common.NewError("host is empty")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, common.NewError("invalid port")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ip, err := resolveAllowedIP(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(p)))
}

func validateExternalURL(u *url.URL) error {
	if u == nil || u.Hostname() == "" {
		return common.NewError("missing host")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return common.NewError("unsupported url scheme")
	}
	if u.User != nil {
		return common.NewError("url userinfo is not allowed")
	}
	p := u.Port()
	if p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return common.NewError("invalid port")
		}
	}
	return rejectUnsafeHost(context.Background(), u.Hostname())
}

func rejectUnsafeHost(ctx context.Context, host string) error {
	_, err := resolveAllowedIP(ctx, host)
	return err
}

func resolveAllowedIP(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if isUnsafeIP(ip) {
			return netip.Addr{}, common.NewError("target address is not allowed")
		}
		return ip, nil
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range addrs {
		if !isUnsafeIP(ip) {
			return ip, nil
		}
	}
	return netip.Addr{}, common.NewError("target resolves only to blocked addresses")
}

func isUnsafeIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip == netip.MustParseAddr("169.254.169.254") || ip == netip.MustParseAddr("100.100.100.200") {
		return true
	}
	return false
}
