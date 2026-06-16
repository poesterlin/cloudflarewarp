// Package cloudflarewarp Traefik Plugin.
package cloudflarewarp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/BetterCorp/cloudflarewarp/ips"
)

const (
	xRealIP        = "X-Real-Ip"
	xCfTrusted     = "X-Is-Trusted"
	xForwardFor    = "X-Forwarded-For"
	xForwardProto  = "X-Forwarded-Proto"
	cfConnectingIP = "CF-Connecting-IP"
	cfVisitor      = "CF-Visitor"
)

// Config the plugin configuration.
type Config struct {
	TrustIP             []string `json:"trustip,omitempty"`
	DisableDefaultCFIPs bool     `json:"disableDefault,omitempty"`
}

// TrustResult for Trust IP test result.
type TrustResult struct {
	isFatal  bool
	isError  bool
	trusted  bool
	directIP string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TrustIP:             []string{},
		DisableDefaultCFIPs: false,
	}
}

// RealIPOverWriter is a plugin that overwrite true IP.
type RealIPOverWriter struct {
	next    http.Handler
	name    string
	TrustIP []*net.IPNet
}

// CFVisitorHeader definition for the header value.
type CFVisitorHeader struct {
	Scheme string `json:"scheme"`
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	ipOverWriter := &RealIPOverWriter{
		next: next,
		name: name,
	}

	if config.TrustIP != nil {
		for _, v := range config.TrustIP {
			_, trustip, err := net.ParseCIDR(v)
			if err != nil {
				return nil, err
			}

			ipOverWriter.TrustIP = append(ipOverWriter.TrustIP, trustip)
		}
	}

	if !config.DisableDefaultCFIPs {
		for _, v := range ips.CFIPs() {
			_, trustip, err := net.ParseCIDR(v)
			if err != nil {
				return nil, err
			}

			ipOverWriter.TrustIP = append(ipOverWriter.TrustIP, trustip)
		}
	}

	return ipOverWriter, nil
}
// Helper to optionally extract real IP from Cloudflare headers.
// Returns true if Cloudflare headers were present and valid, false otherwise.
func (r *RealIPOverWriter) trySetCFHeaders(req *http.Request) bool {
	if req.Header.Get("Cf-Visitor") == "" {
		return false
	}
	var visitor CFVisitorHeader
	if err := json.Unmarshal([]byte(req.Header.Get("Cf-Visitor")), &visitor); err != nil {
		// Malformed Cloudflare header – treat as untrusted
		req.Header.Set("X-Is-Trusted", "danger")
		req.Header.Del("Cf-Visitor")
		req.Header.Del("Cf-Connecting-Ip")
		return false
	}
	req.Header.Set("X-Forwarded-Proto", visitor.Scheme)
	cfIP := req.Header.Get("Cf-Connecting-Ip")
	if cfIP != "" {
		req.Header.Set("X-Forwarded-For", cfIP)
		req.Header.Set("X-Real-Ip", cfIP)
	}
	req.Header.Set("X-Is-Trusted", "yes")
	return true
}

func (r *RealIPOverWriter) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	trustResult := r.trust(req.RemoteAddr)
	if trustResult.isFatal {
		http.Error(rw, "Unknown source", http.StatusInternalServerError)
		return
	}
	if trustResult.isError {
		http.Error(rw, "Unknown source", http.StatusBadRequest)
		return
	}
	if trustResult.directIP == "" {
		http.Error(rw, "Unknown source", http.StatusUnprocessableEntity)
		return
	}

	if trustResult.trusted && r.trySetCFHeaders(req) {
		// Cloudflare handling done; nothing more needed
	} else {
		// Not trusted or no Cloudflare headers
		req.Header.Set("X-Is-Trusted", "no")
		req.Header.Set("X-Real-Ip", trustResult.directIP)
		req.Header.Del("Cf-Visitor")
		req.Header.Del("Cf-Connecting-Ip")
	}
	r.next.ServeHTTP(rw, req)
}

func (r *RealIPOverWriter) trust(s string) *TrustResult {
	temp, _, err := net.SplitHostPort(s)
	if err != nil {
		return &TrustResult{
			isFatal:  true,
			isError:  true,
			trusted:  false,
			directIP: "",
		}
	}
	ip := net.ParseIP(temp)
	if ip == nil {
		return &TrustResult{
			isFatal:  false,
			isError:  true,
			trusted:  false,
			directIP: "",
		}
	}
	for _, network := range r.TrustIP {
		if network.Contains(ip) {
			return &TrustResult{
				isFatal:  false,
				isError:  false,
				trusted:  true,
				directIP: ip.String(),
			}
		}
	}
	return &TrustResult{
		isFatal:  false,
		isError:  false,
		trusted:  false,
		directIP: ip.String(),
	}
}
