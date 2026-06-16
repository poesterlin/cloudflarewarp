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
	cfConnectingIP = "Cf-Connecting-Ip"
	cfVisitor      = "Cf-Visitor"
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
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
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

// hasCloudflareHeaders reports whether Cloudflare-specific headers are present,
// even when their values are blank.
func hasCloudflareHeaders(req *http.Request) bool {
	_, hasCFVisitor := req.Header[cfVisitor]
	_, hasCFConnecting := req.Header[cfConnectingIP]

	return hasCFVisitor || hasCFConnecting
}

func setCloudflareHeaders(req *http.Request) bool {
	cfVisitorValue := req.Header.Get(cfVisitor)
	if cfVisitorValue != "" {
		var visitor CFVisitorHeader
		if err := json.Unmarshal([]byte(cfVisitorValue), &visitor); err != nil {
			req.Header.Set(xCfTrusted, "danger")
			req.Header.Del(cfVisitor)
			req.Header.Del(cfConnectingIP)
			return false
		}
		req.Header.Set(xForwardProto, visitor.Scheme)
	}

	req.Header.Set(xCfTrusted, "yes")
	req.Header.Set(xForwardFor, req.Header.Get(cfConnectingIP))
	req.Header.Set(xRealIP, req.Header.Get(cfConnectingIP))

	return true
}

func setDirectHeaders(req *http.Request, directIP string) {
	req.Header.Set(xCfTrusted, "no")
	req.Header.Set(xRealIP, directIP)
	req.Header.Del(cfVisitor)
	req.Header.Del(cfConnectingIP)
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

	if trustResult.trusted && hasCloudflareHeaders(req) {
		if !setCloudflareHeaders(req) {
			r.next.ServeHTTP(rw, req)
			return
		}
	} else {
		setDirectHeaders(req, trustResult.directIP)
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
