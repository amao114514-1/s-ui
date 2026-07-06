package api

import (
	"crypto/subtle"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alireza0/s-ui/util/common"

	"github.com/gin-gonic/gin"
)

var certPingRate = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

func checkCSRF(c *gin.Context) error {
	expected := GetCSRFToken(c)
	provided := c.GetHeader("X-CSRF-Token")
	if provided == "" {
		provided = c.PostForm("_csrf")
	}
	if expected == "" || provided == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
		return common.NewError("invalid csrf token")
	}
	return nil
}

func checkSameOrigin(c *gin.Context, configuredDomain string) error {
	source := c.GetHeader("Origin")
	if source == "" {
		source = c.GetHeader("Referer")
	}
	if source == "" {
		return common.NewError("missing origin")
	}

	parsed, err := url.Parse(source)
	if err != nil || parsed.Host == "" {
		return common.NewError("invalid origin")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return common.NewError("invalid origin scheme")
	}

	allowedHosts := map[string]bool{}
	if c.Request.Host != "" {
		allowedHosts[strings.ToLower(c.Request.Host)] = true
		if host, _, err := net.SplitHostPort(c.Request.Host); err == nil {
			allowedHosts[strings.ToLower(host)] = true
		}
	}
	if configuredDomain != "" {
		allowedHosts[strings.ToLower(configuredDomain)] = true
	}

	originHost := strings.ToLower(parsed.Host)
	if allowedHosts[originHost] {
		return nil
	}
	if host, _, err := net.SplitHostPort(parsed.Host); err == nil && allowedHosts[strings.ToLower(host)] {
		return nil
	}
	return common.NewError("origin not allowed")
}

func checkCertPingRate(c *gin.Context) error {
	key := getRemoteIp(c)
	if key == "" {
		key = c.ClientIP()
	}
	now := time.Now()
	certPingRate.Lock()
	defer certPingRate.Unlock()
	if last, ok := certPingRate.last[key]; ok && now.Sub(last) < 5*time.Second {
		return common.NewError("rate limited")
	}
	certPingRate.last[key] = now
	return nil
}

func requireRecentLogin(c *gin.Context) error {
	if IsRecentLogin(c, 15*time.Minute) {
		return nil
	}
	return common.NewError("recent login required")
}
