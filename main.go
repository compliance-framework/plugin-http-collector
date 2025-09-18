package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

// HttpCollectorConfig holds the configuration for the HTTP collector plugin
// This matches the config sample structure from the requirements
type HttpCollectorConfig struct {
	URL               string `json:"url"`
	Method            string `json:"method"`
	Timeout           int    `json:"timeout"`
	BasicAuth         bool   `json:"basic_auth"`
	BasicAuthUsername string `json:"basic_auth_username"`
	BasicAuthPassword string `json:"basic_auth_password"`
	AdditionalHeaders string `json:"additional_headers"`
	CheckCertificate  bool   `json:"check_certificate"`
	BodyRegexPattern  string `json:"body_regex_pattern"`
}

// TLSInfo represents SSL/TLS certificate and connection information
type TLSInfo struct {
	Version            string   `json:"version"`              // TLS version (e.g., "1.3", "1.2")
	CipherSuite        string   `json:"cipher_suite"`         // Cipher suite used
	ServerName         string   `json:"server_name"`          // SNI server name
	PeerCertificates   []string `json:"peer_certificates"`    // Certificate chain (PEM format)
	VerifiedChains     bool     `json:"verified_chains"`      // Certificate chain verification status
	HandshakeComplete  bool     `json:"handshake_complete"`   // TLS handshake success
	HandshakeTime      int64    `json:"handshake_time_ms"`    // TLS handshake duration
}

// RedirectInfo represents HTTP redirect chain information
type RedirectInfo struct {
	URL        string `json:"url"`         // Redirect target URL
	StatusCode int    `json:"status_code"` // Redirect status code (301, 302, etc.)
	Method     string `json:"method"`      // HTTP method after redirect
}

// TimingInfo represents detailed timing breakdown
type TimingInfo struct {
	DNSLookup        int64 `json:"dns_lookup_ms"`        // DNS resolution time
	TCPConnection    int64 `json:"tcp_connection_ms"`    // TCP connection establishment
	TLSHandshake     int64 `json:"tls_handshake_ms"`     // TLS handshake time
	ServerProcessing int64 `json:"server_processing_ms"` // Time to first byte
	ContentTransfer  int64 `json:"content_transfer_ms"`  // Content download time
	TotalTime        int64 `json:"total_time_ms"`        // Total request time
}

// SecurityHeaders represents security-related HTTP headers analysis
type SecurityHeaders struct {
	StrictTransportSecurity   string `json:"strict_transport_security,omitempty"`   // HSTS header
	ContentSecurityPolicy     string `json:"content_security_policy,omitempty"`     // CSP header
	XFrameOptions            string `json:"x_frame_options,omitempty"`             // X-Frame-Options
	XContentTypeOptions      string `json:"x_content_type_options,omitempty"`      // X-Content-Type-Options
	XSSProtection            string `json:"x_xss_protection,omitempty"`            // X-XSS-Protection
	ReferrerPolicy           string `json:"referrer_policy,omitempty"`             // Referrer-Policy
	PermissionsPolicy        string `json:"permissions_policy,omitempty"`          // Permissions-Policy
	CrossOriginEmbedderPolicy string `json:"cross_origin_embedder_policy,omitempty"` // COEP
	CrossOriginOpenerPolicy   string `json:"cross_origin_opener_policy,omitempty"`   // COOP
	CrossOriginResourcePolicy string `json:"cross_origin_resource_policy,omitempty"` // CORP
}

// CompressionInfo represents response compression and encoding details
type CompressionInfo struct {
	ContentEncoding    string `json:"content_encoding,omitempty"`    // gzip, deflate, br, etc.
	TransferEncoding   string `json:"transfer_encoding,omitempty"`   // chunked, etc.
	ContentLength      int64  `json:"content_length"`                // Original content length
	CompressedSize     int64  `json:"compressed_size"`               // Compressed response size
	CompressionRatio   float64 `json:"compression_ratio,omitempty"`   // Compression efficiency
}

// HttpResponseData represents the comprehensive structured response data
// Enhanced with security, performance, and compliance metrics
type HttpResponseData struct {
	// Basic HTTP Response Data
	StatusCode       int                 `json:"status_code"`
	Status           string              `json:"status"`
	Headers          map[string][]string `json:"headers"`
	Body             string              `json:"body"`
	Success          bool                `json:"success"`                      // true if 200 <= status < 300
	Error            string              `json:"error,omitempty"`              // only if request failed
	MatchedRegex     bool                `json:"matched_regex,omitempty"`      // only if regex pattern provided
	BodyRegexPattern string              `json:"body_regex_pattern,omitempty"` // echo back the pattern used

	// Enhanced Timing and Performance Metrics
	ResponseTime     int64        `json:"response_time_ms"`     // Total response time (backward compatibility)
	Timing          *TimingInfo   `json:"timing,omitempty"`     // Detailed timing breakdown

	// Security and TLS Information
	TLS             *TLSInfo         `json:"tls,omitempty"`             // SSL/TLS certificate and connection info
	SecurityHeaders *SecurityHeaders `json:"security_headers,omitempty"` // Security-related headers analysis

	// Redirect Chain Analysis
	Redirects       []RedirectInfo   `json:"redirects,omitempty"`       // Complete redirect chain
	FinalURL        string           `json:"final_url,omitempty"`       // Final URL after redirects
	RedirectCount   int              `json:"redirect_count"`            // Number of redirects followed

	// Content Analysis
	Compression     *CompressionInfo `json:"compression,omitempty"`     // Compression and encoding details
	ContentType     string           `json:"content_type,omitempty"`    // Parsed content type
	Charset         string           `json:"charset,omitempty"`         // Character encoding
	BodySize        int64            `json:"body_size"`                 // Response body size in bytes

	// DNS and Network Information
	ResolvedIPs     []string         `json:"resolved_ips,omitempty"`    // All resolved IP addresses
	RemoteAddr      string           `json:"remote_addr,omitempty"`     // Actual server IP:port connected to
}

// HttpResponseDataForPolicy represents a policy-compatible version of HttpResponseData
// with simplified header structure to avoid policy manager issues
type HttpResponseDataForPolicy struct {
	StatusCode       int               `json:"status_code"`
	Status           string            `json:"status"`
	Headers          map[string]string `json:"headers"`          // Simplified: single string values
	Body             string            `json:"body"`
	ResponseTime     int64             `json:"response_time_ms"`
	Success          bool              `json:"success"`
	Error            string            `json:"error,omitempty"`
	MatchedRegex     bool              `json:"matched_regex,omitempty"`
	BodyRegexPattern string            `json:"body_regex_pattern,omitempty"`
}

// HttpCollectorPlugin implements the Runner interface
type HttpCollectorPlugin struct {
	logger hclog.Logger
	config *HttpCollectorConfig
}

// Validate ensures the configuration is valid
func (c *HttpCollectorConfig) Validate() error {
	if c.URL == "" {
		return fmt.Errorf("url is required in configuration")
	}

	// Validate URL format and ensure it's HTTP/HTTPS
	parsedURL, err := url.Parse(c.URL)
	if err != nil || parsedURL.Scheme == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return fmt.Errorf("invalid url format: must be a valid HTTP or HTTPS URL")
	}

	return nil
}

// Configure implements runner.Runner
// This is called by the agent to provide configuration to the plugin
func (p *HttpCollectorPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	p.logger.Info("Configuring HTTP collector plugin")

	// Initialize with defaults
	config := &HttpCollectorConfig{
		Method:           "GET",
		Timeout:          5000,
		CheckCertificate: true, // default to secure
	}

	// Parse configuration from the agent (all values come as strings)
	for key, value := range req.Config {
		switch key {
		case "url":
			config.URL = value
		case "method":
			config.Method = strings.ToUpper(value)
		case "timeout":
			if timeout, err := strconv.Atoi(value); err == nil {
				config.Timeout = timeout
			}
		case "basic_auth":
			// Handle various boolean representations
			lowerValue := strings.ToLower(value)
			config.BasicAuth = lowerValue == "true" || lowerValue == "1" || lowerValue == "yes"
		case "basic_auth_username":
			config.BasicAuthUsername = value
		case "basic_auth_password":
			config.BasicAuthPassword = value
		case "additional_headers":
			config.AdditionalHeaders = value
		case "check_certificate":
			config.CheckCertificate = strings.ToLower(value) != "false"
		case "body_regex_pattern":
			config.BodyRegexPattern = value
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		p.logger.Error("Error validating config", "error", err)
		return nil, err
	}

	p.config = config
	p.logger.Info("HTTP collector configured successfully",
		"url", config.URL,
		"method", config.Method,
		"timeout", config.Timeout)

	return &proto.ConfigureResponse{}, nil
}

// extractSecurityHeaders analyzes HTTP response headers for security-related information
func extractSecurityHeaders(headers http.Header) *SecurityHeaders {
	secHeaders := &SecurityHeaders{}

	// Extract key security headers
	if hsts := headers.Get("Strict-Transport-Security"); hsts != "" {
		secHeaders.StrictTransportSecurity = hsts
	}
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		secHeaders.ContentSecurityPolicy = csp
	}
	if xframe := headers.Get("X-Frame-Options"); xframe != "" {
		secHeaders.XFrameOptions = xframe
	}
	if xcontent := headers.Get("X-Content-Type-Options"); xcontent != "" {
		secHeaders.XContentTypeOptions = xcontent
	}
	if xxss := headers.Get("X-XSS-Protection"); xxss != "" {
		secHeaders.XSSProtection = xxss
	}
	if referrer := headers.Get("Referrer-Policy"); referrer != "" {
		secHeaders.ReferrerPolicy = referrer
	}
	if permissions := headers.Get("Permissions-Policy"); permissions != "" {
		secHeaders.PermissionsPolicy = permissions
	}
	if coep := headers.Get("Cross-Origin-Embedder-Policy"); coep != "" {
		secHeaders.CrossOriginEmbedderPolicy = coep
	}
	if coop := headers.Get("Cross-Origin-Opener-Policy"); coop != "" {
		secHeaders.CrossOriginOpenerPolicy = coop
	}
	if corp := headers.Get("Cross-Origin-Resource-Policy"); corp != "" {
		secHeaders.CrossOriginResourcePolicy = corp
	}

	return secHeaders
}

// extractTLSInfo analyzes TLS connection information from the response
func extractTLSInfo(connState *tls.ConnectionState) *TLSInfo {
	if connState == nil {
		return nil
	}

	tlsInfo := &TLSInfo{
		HandshakeComplete: connState.HandshakeComplete,
		ServerName:       connState.ServerName,
		VerifiedChains:   len(connState.VerifiedChains) > 0,
	}

	// Get TLS version
	switch connState.Version {
	case tls.VersionTLS13:
		tlsInfo.Version = "1.3"
	case tls.VersionTLS12:
		tlsInfo.Version = "1.2"
	case tls.VersionTLS11:
		tlsInfo.Version = "1.1"
	case tls.VersionTLS10:
		tlsInfo.Version = "1.0"
	default:
		tlsInfo.Version = fmt.Sprintf("unknown(0x%04x)", connState.Version)
	}

	// Get cipher suite
	tlsInfo.CipherSuite = tls.CipherSuiteName(connState.CipherSuite)

	// Extract certificate information
	if len(connState.PeerCertificates) > 0 {
		tlsInfo.PeerCertificates = make([]string, len(connState.PeerCertificates))
		for i, cert := range connState.PeerCertificates {
			// Convert certificate to PEM format
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			tlsInfo.PeerCertificates[i] = string(certPEM)
		}
	}

	return tlsInfo
}

// extractCompressionInfo analyzes response compression and encoding
func extractCompressionInfo(headers http.Header, bodySize int64) *CompressionInfo {
	compression := &CompressionInfo{
		CompressedSize: bodySize,
	}

	// Extract encoding information
	if contentEncoding := headers.Get("Content-Encoding"); contentEncoding != "" {
		compression.ContentEncoding = contentEncoding
	}
	if transferEncoding := headers.Get("Transfer-Encoding"); transferEncoding != "" {
		compression.TransferEncoding = transferEncoding
	}

	// Extract content length (original size)
	if contentLengthStr := headers.Get("Content-Length"); contentLengthStr != "" {
		if contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64); err == nil {
			compression.ContentLength = contentLength
		}
	}

	// Calculate compression ratio if both sizes are available
	if compression.ContentLength > 0 && compression.CompressedSize > 0 {
		compression.CompressionRatio = float64(compression.CompressedSize) / float64(compression.ContentLength)
	}

	return compression
}

// parseContentType extracts content type and charset from Content-Type header
func parseContentType(contentType string) (mediaType, charset string) {
	parts := strings.Split(contentType, ";")
	if len(parts) > 0 {
		mediaType = strings.TrimSpace(parts[0])
	}

	// Look for charset parameter
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "charset=") {
			charset = strings.TrimPrefix(part, "charset=")
			charset = strings.Trim(charset, "\"")
			break
		}
	}

	return mediaType, charset
}

// makeHttpRequest performs the HTTP request and returns comprehensive structured response data
func (p *HttpCollectorPlugin) makeHttpRequest() (*HttpResponseData, error) {
	startTime := time.Now()

	// Initialize timing information with httptrace
	var timing TimingInfo
	var dnsStart, dnsEnd, connStart, connEnd, tlsStart, tlsEnd time.Time
	var gotFirstResponseByte time.Time
	var resolvedIPs []string
	var remoteAddr string

	// Create HTTP trace to capture detailed timing
	trace := &httptrace.ClientTrace{
		DNSStart: func(dnsStartInfo httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(dnsDoneInfo httptrace.DNSDoneInfo) {
			dnsEnd = time.Now()
			if dnsDoneInfo.Err == nil {
				for _, addr := range dnsDoneInfo.Addrs {
					resolvedIPs = append(resolvedIPs, addr.IP.String())
				}
			}
		},
		ConnectStart: func(network, addr string) {
			connStart = time.Now()
		},
		ConnectDone: func(network, addr string, err error) {
			connEnd = time.Now()
			if err == nil {
				remoteAddr = addr
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			tlsEnd = time.Now()
		},
		GotFirstResponseByte: func() {
			gotFirstResponseByte = time.Now()
		},
	}

	// Create HTTP request with trace context
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), p.config.Method, p.config.URL, nil)
	if err != nil {
		return &HttpResponseData{
			Success:      false,
			Error:        fmt.Sprintf("failed to create request: %v", err),
			ResponseTime: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Add basic authentication if configured
	if p.config.BasicAuth && p.config.BasicAuthUsername != "" {
		req.SetBasicAuth(p.config.BasicAuthUsername, p.config.BasicAuthPassword)
		p.logger.Debug("Added basic authentication")
	}

	// Parse and add additional headers
	if p.config.AdditionalHeaders != "" {
		headers := strings.Split(p.config.AdditionalHeaders, ";")
		for _, header := range headers {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
		p.logger.Debug("Added additional headers", "count", len(headers))
	}

	// Create HTTP client with custom transport for redirect tracking
	var redirects []RedirectInfo
	client := &http.Client{
		Timeout: time.Duration(p.config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !p.config.CheckCertificate,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Track redirect chain
			if len(via) > 0 {
				prevReq := via[len(via)-1]
				redirects = append(redirects, RedirectInfo{
					URL:        prevReq.URL.String(),
					StatusCode: 0, // We'll get this from response
					Method:     req.Method,
				})
			}
			// Allow up to 10 redirects (default Go behavior)
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	// Execute the HTTP request
	resp, err := client.Do(req)
	requestEndTime := time.Now()

	if err != nil {
		// Calculate timing even for failed requests
		totalTime := requestEndTime.Sub(startTime).Milliseconds()
		return &HttpResponseData{
			Success:      false,
			Error:        fmt.Sprintf("HTTP request failed: %v", err),
			ResponseTime: totalTime,
			Timing: &TimingInfo{
				TotalTime: totalTime,
			},
			ResolvedIPs: resolvedIPs,
			RemoteAddr:  remoteAddr,
		}, nil
	}
	defer resp.Body.Close()

	// Calculate detailed timing information
	if !dnsStart.IsZero() && !dnsEnd.IsZero() {
		timing.DNSLookup = dnsEnd.Sub(dnsStart).Milliseconds()
	}
	if !connStart.IsZero() && !connEnd.IsZero() {
		timing.TCPConnection = connEnd.Sub(connStart).Milliseconds()
	}
	if !tlsStart.IsZero() && !tlsEnd.IsZero() {
		timing.TLSHandshake = tlsEnd.Sub(tlsStart).Milliseconds()
	}
	if !gotFirstResponseByte.IsZero() {
		timing.ServerProcessing = gotFirstResponseByte.Sub(startTime).Milliseconds()
	}

	// Read response body
	bodyStartTime := time.Now()
	body, err := io.ReadAll(resp.Body)
	bodyEndTime := time.Now()

	if err != nil {
		totalTime := requestEndTime.Sub(startTime).Milliseconds()
		return &HttpResponseData{
			Success:      false,
			Error:        fmt.Sprintf("failed to read response body: %v", err),
			StatusCode:   resp.StatusCode,
			Status:       resp.Status,
			Headers:      resp.Header,
			ResponseTime: totalTime,
			Timing:       &timing,
			ResolvedIPs:  resolvedIPs,
			RemoteAddr:   remoteAddr,
		}, nil
	}

	// Complete timing calculations
	timing.ContentTransfer = bodyEndTime.Sub(bodyStartTime).Milliseconds()
	timing.TotalTime = bodyEndTime.Sub(startTime).Milliseconds()

	// Parse final URL after potential redirects
	finalURL := resp.Request.URL.String()

	// Check if status code indicates success (200 <= x < 300)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	// Extract content type and charset
	contentTypeHeader := resp.Header.Get("Content-Type")
	contentType, charset := parseContentType(contentTypeHeader)

	// Analyze response data with helper functions
	securityHeaders := extractSecurityHeaders(resp.Header)
	tlsInfo := extractTLSInfo(resp.TLS)
	compression := extractCompressionInfo(resp.Header, int64(len(body)))

	// Build comprehensive response data
	responseData := &HttpResponseData{
		// Basic HTTP Response Data
		StatusCode:       resp.StatusCode,
		Status:           resp.Status,
		Headers:          resp.Header,
		Body:            string(body),
		Success:         success,
		ResponseTime:    timing.TotalTime, // Backward compatibility

		// Enhanced Timing and Performance Metrics
		Timing:          &timing,

		// Security and TLS Information
		TLS:             tlsInfo,
		SecurityHeaders: securityHeaders,

		// Redirect Chain Analysis
		Redirects:       redirects,
		FinalURL:        finalURL,
		RedirectCount:   len(redirects),

		// Content Analysis
		Compression:     compression,
		ContentType:     contentType,
		Charset:         charset,
		BodySize:        int64(len(body)),

		// DNS and Network Information
		ResolvedIPs:     resolvedIPs,
		RemoteAddr:      remoteAddr,
	}

	// Check regex pattern if configured
	if p.config.BodyRegexPattern != "" {
		matched, err := regexp.MatchString(p.config.BodyRegexPattern, string(body))
		if err != nil {
			p.logger.Warn("Invalid regex pattern", "pattern", p.config.BodyRegexPattern, "error", err)
		} else {
			responseData.MatchedRegex = matched
			responseData.BodyRegexPattern = p.config.BodyRegexPattern
			p.logger.Debug("Regex pattern check", "pattern", p.config.BodyRegexPattern, "matched", matched)
		}
	}

	// Enhanced logging with more metrics
	p.logger.Info("HTTP request completed with enhanced metrics",
		"status", resp.StatusCode,
		"success", success,
		"total_time_ms", timing.TotalTime,
		"dns_time_ms", timing.DNSLookup,
		"tcp_time_ms", timing.TCPConnection,
		"tls_time_ms", timing.TLSHandshake,
		"content_size", len(body),
		"redirects", len(redirects),
		"resolved_ips", len(resolvedIPs))

	return responseData, nil
}

// enhanceEvidenceWithHttpData adds comprehensive HTTP metrics as Props to Evidence objects
// This allows storing enhanced HTTP data in the database without touching /agent code
func (p *HttpCollectorPlugin) enhanceEvidenceWithHttpData(evidences []*proto.Evidence, responseData *HttpResponseData) {
	// Convert enhanced HTTP data to Proto Properties
	httpProps := []*proto.Property{
		// Performance Timing Metrics
		{
			Name:  "http_dns_lookup_ms",
			Value: fmt.Sprintf("%d", responseData.Timing.DNSLookup),
			Class: policyManager.Pointer("performance-metric"),
			Remarks: policyManager.Pointer("DNS resolution time in milliseconds"),
		},
		{
			Name:  "http_tcp_connection_ms",
			Value: fmt.Sprintf("%d", responseData.Timing.TCPConnection),
			Class: policyManager.Pointer("performance-metric"),
			Remarks: policyManager.Pointer("TCP connection establishment time in milliseconds"),
		},
		{
			Name:  "http_tls_handshake_ms",
			Value: fmt.Sprintf("%d", responseData.Timing.TLSHandshake),
			Class: policyManager.Pointer("security-metric"),
			Remarks: policyManager.Pointer("TLS handshake time in milliseconds"),
		},
		{
			Name:  "http_server_processing_ms",
			Value: fmt.Sprintf("%d", responseData.Timing.ServerProcessing),
			Class: policyManager.Pointer("performance-metric"),
			Remarks: policyManager.Pointer("Time to first byte from server in milliseconds"),
		},
		{
			Name:  "http_content_transfer_ms",
			Value: fmt.Sprintf("%d", responseData.Timing.ContentTransfer),
			Class: policyManager.Pointer("performance-metric"),
			Remarks: policyManager.Pointer("Content download time in milliseconds"),
		},

		// Content Analysis Metrics
		{
			Name:  "http_content_size_bytes",
			Value: fmt.Sprintf("%d", responseData.BodySize),
			Class: policyManager.Pointer("content-metric"),
			Remarks: policyManager.Pointer("Response body size in bytes"),
		},
		{
			Name:  "http_content_type",
			Value: responseData.ContentType,
			Class: policyManager.Pointer("content-classification"),
			Remarks: policyManager.Pointer("Parsed content type from response headers"),
		},
		{
			Name:  "http_charset",
			Value: responseData.Charset,
			Class: policyManager.Pointer("content-encoding"),
			Remarks: policyManager.Pointer("Character encoding from content-type header"),
		},

		// Network Information
		{
			Name:  "http_resolved_ips",
			Value: strings.Join(responseData.ResolvedIPs, ","),
			Class: policyManager.Pointer("network-topology"),
			Remarks: policyManager.Pointer("All IP addresses resolved for the target hostname"),
		},
		{
			Name:  "http_remote_addr",
			Value: responseData.RemoteAddr,
			Class: policyManager.Pointer("network-endpoint"),
			Remarks: policyManager.Pointer("Actual server IP address and port connected to"),
		},
		{
			Name:  "http_final_url",
			Value: responseData.FinalURL,
			Class: policyManager.Pointer("endpoint-configuration"),
			Remarks: policyManager.Pointer("Final URL after following any redirects"),
		},
		{
			Name:  "http_redirect_count",
			Value: fmt.Sprintf("%d", responseData.RedirectCount),
			Class: policyManager.Pointer("security-analysis"),
			Remarks: policyManager.Pointer("Number of HTTP redirects followed"),
		},
	}

	// Add TLS Security Information if available
	if responseData.TLS != nil {
		tlsProps := []*proto.Property{
			{
				Name:  "tls_version",
				Value: responseData.TLS.Version,
				Class: policyManager.Pointer("security-protocol"),
				Remarks: policyManager.Pointer("TLS protocol version used for the connection"),
			},
			{
				Name:  "tls_cipher_suite",
				Value: responseData.TLS.CipherSuite,
				Class: policyManager.Pointer("security-encryption"),
				Remarks: policyManager.Pointer("TLS cipher suite negotiated for the connection"),
			},
			{
				Name:  "tls_server_name",
				Value: responseData.TLS.ServerName,
				Class: policyManager.Pointer("security-identity"),
				Remarks: policyManager.Pointer("SNI server name used in TLS handshake"),
			},
			{
				Name:  "tls_handshake_complete",
				Value: fmt.Sprintf("%t", responseData.TLS.HandshakeComplete),
				Class: policyManager.Pointer("security-status"),
				Remarks: policyManager.Pointer("Whether TLS handshake completed successfully"),
			},
			{
				Name:  "tls_verified_chains",
				Value: fmt.Sprintf("%t", responseData.TLS.VerifiedChains),
				Class: policyManager.Pointer("security-validation"),
				Remarks: policyManager.Pointer("Whether certificate chains were successfully verified"),
			},
		}
		httpProps = append(httpProps, tlsProps...)
	}

	// Add Security Headers Analysis if available
	if responseData.SecurityHeaders != nil {
		if responseData.SecurityHeaders.StrictTransportSecurity != "" {
			httpProps = append(httpProps, &proto.Property{
				Name:  "security_header_hsts",
				Value: responseData.SecurityHeaders.StrictTransportSecurity,
				Class: policyManager.Pointer("security-header"),
				Remarks: policyManager.Pointer("HTTP Strict Transport Security header value"),
			})
		}
		if responseData.SecurityHeaders.ContentSecurityPolicy != "" {
			httpProps = append(httpProps, &proto.Property{
				Name:  "security_header_csp",
				Value: responseData.SecurityHeaders.ContentSecurityPolicy,
				Class: policyManager.Pointer("security-header"),
				Remarks: policyManager.Pointer("Content Security Policy header value"),
			})
		}
		if responseData.SecurityHeaders.XFrameOptions != "" {
			httpProps = append(httpProps, &proto.Property{
				Name:  "security_header_x_frame_options",
				Value: responseData.SecurityHeaders.XFrameOptions,
				Class: policyManager.Pointer("security-header"),
				Remarks: policyManager.Pointer("X-Frame-Options header for clickjacking protection"),
			})
		}
		if responseData.SecurityHeaders.XContentTypeOptions != "" {
			httpProps = append(httpProps, &proto.Property{
				Name:  "security_header_x_content_type_options",
				Value: responseData.SecurityHeaders.XContentTypeOptions,
				Class: policyManager.Pointer("security-header"),
				Remarks: policyManager.Pointer("X-Content-Type-Options header for MIME type sniffing protection"),
			})
		}
	}

	// Add Compression Information if available
	if responseData.Compression != nil && responseData.Compression.ContentEncoding != "" {
		httpProps = append(httpProps, &proto.Property{
			Name:  "http_content_encoding",
			Value: responseData.Compression.ContentEncoding,
			Class: policyManager.Pointer("content-optimization"),
			Remarks: policyManager.Pointer("Content encoding used for compression (gzip, deflate, br, etc.)"),
		})
		if responseData.Compression.CompressionRatio > 0 {
			httpProps = append(httpProps, &proto.Property{
				Name:  "http_compression_ratio",
				Value: fmt.Sprintf("%.2f", responseData.Compression.CompressionRatio),
				Class: policyManager.Pointer("performance-optimization"),
				Remarks: policyManager.Pointer("Compression ratio (compressed_size / original_size)"),
			})
		}
	}

	// Add Props to each Evidence object
	for _, evidence := range evidences {
		evidence.Props = append(evidence.Props, httpProps...)
	}

	p.logger.Debug("Enhanced evidence with HTTP data", "properties_added", len(httpProps), "evidence_count", len(evidences))
}

// processHeaders converts HTTP headers from multi-value format to policy-compatible format
// Policies expect headers as nested map: input.headers["Content-Type"]
func processHeaders(headers map[string][]string) map[string]interface{} {
	headersMap := make(map[string]interface{})
	for key, values := range headers {
		if len(values) > 0 {
			if len(values) == 1 {
				headersMap[key] = values[0]
			} else {
				headersMap[key] = values
			}
		}
	}
	return headersMap
}

// EvaluatePolicies processes policies against HTTP response data using the policy manager
func (p *HttpCollectorPlugin) EvaluatePolicies(ctx context.Context, responseData *HttpResponseData, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)

	// Add HTTP data collection activity (with placeholder data)
	activities = append(activities, &proto.Activity{
		Title:       "Collect HTTP endpoint data",
		Description: "Execute HTTP request and collect response data for policy validation",
		Steps: []*proto.Step{
			{
				Title:       "Configure HTTP Client",
				Description: fmt.Sprintf("Set timeout: %dms, certificate check: %t, basic auth: %t", p.config.Timeout, p.config.CheckCertificate, p.config.BasicAuth),
			},
			{
				Title:       "Execute HTTP Request",
				Description: fmt.Sprintf("Made %s request to %s", p.config.Method, p.config.URL),
			},
			{
				Title:       "Process Response",
				Description: "Received HTTP response and processed response data",
			},
		},
	})

	// Rich OSCAL metadata implementation matching SSH/GitHub plugin patterns
	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework Documentation"),
				},
			},
		},
		{
			Title: "Continuous Compliance Framework - HTTP Collector Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-http-collector",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("HTTP Collector Plugin Repository"),
				},
			},
		},
	}

	components := []*proto.Component{
		{
			Identifier:  "common-components/http-endpoint",
			Type:        "service",
			Title:       "HTTP Endpoint",
			Description: "An HTTP/HTTPS endpoint that provides web services, APIs, or web applications accessible over the internet or internal networks. HTTP endpoints are critical infrastructure components that require security monitoring and compliance validation.",
			Purpose:     "To provide web services, REST APIs, or web applications while maintaining security standards, availability requirements, and compliance with organizational policies for data protection and service delivery.",
			Protocols: []*proto.Protocol{
				{
					Name:  "HTTP",
					Title: "Hypertext Transfer Protocol",
				},
				{
					Name:  "HTTPS",
					Title: "HTTP Secure (HTTP over TLS)",
				},
			},
		},
		{
			Identifier:  "common-components/web-service",
			Type:        "service",
			Title:       "Web Service",
			Description: "A web service component that provides functionality over HTTP/HTTPS protocols. This includes REST APIs, web applications, microservices, and other HTTP-based services that require monitoring for security, performance, and compliance.",
			Purpose:     "To deliver business functionality through web protocols while ensuring security controls, performance standards, and regulatory compliance are maintained throughout the service lifecycle.",
		},
	}

	// Parse URL to get host information for inventory
	parsedURL, err := url.Parse(p.config.URL)
	if err != nil {
		p.logger.Warn("Failed to parse URL for OSCAL metadata", "url", p.config.URL, "error", err)
		parsedURL = &url.URL{Host: "unknown"}
	}

	// Helper to sanitize identifier strings by replacing unsafe characters with '-'
	sanitizeIdentifier := func(s string) string {
		// Replace all non-alphanumeric, non-dash, non-underscore characters with '-'
		re := regexp.MustCompile(`[^a-zA-Z0-9\-_]`)
		return re.ReplaceAllString(s, "-")
	}

	// Build identifier from scheme, host, and path
	idRaw := fmt.Sprintf("%s-%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	idSafe := sanitizeIdentifier(idRaw)

	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("http-endpoint/%s", idSafe),
			Type:       "http-endpoint",
			Title:      fmt.Sprintf("HTTP Endpoint: %s", parsedURL.Host),
			Description: fmt.Sprintf("HTTP endpoint at %s providing web services that require security monitoring and compliance validation. This endpoint is monitored for availability, security headers, response times, and adherence to organizational policies.", p.config.URL),
			Props: []*proto.Property{
				{
					Name:  "url",
					Value: p.config.URL,
					Class: policyManager.Pointer("endpoint-configuration"),
					Remarks: policyManager.Pointer("The complete URL endpoint being monitored for compliance"),
				},
				{
					Name:  "method",
					Value: p.config.Method,
					Class: policyManager.Pointer("http-configuration"),
					Remarks: policyManager.Pointer("HTTP method used for endpoint monitoring"),
				},
				{
					Name:  "scheme",
					Value: parsedURL.Scheme,
					Class: policyManager.Pointer("security-classification"),
					Remarks: policyManager.Pointer("Protocol scheme indicating encryption status (http vs https)"),
				},
				{
					Name:  "host",
					Value: parsedURL.Host,
					Class: policyManager.Pointer("network-identifier"),
					Remarks: policyManager.Pointer("Target host and port for the monitored endpoint"),
				},
				{
					Name:  "timeout",
					Value: fmt.Sprintf("%d", p.config.Timeout),
					Class: policyManager.Pointer("performance-configuration"),
					Remarks: policyManager.Pointer("Request timeout in milliseconds for availability monitoring"),
				},
			},
			Links: []*proto.Link{
				{
					Href: p.config.URL,
					Text: policyManager.Pointer("Monitored Endpoint"),
					Rel:  policyManager.Pointer("reference"),
				},
				{
					Href: fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host),
					Text: policyManager.Pointer("Base URL"),
					Rel:  policyManager.Pointer("related"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "common-components/http-endpoint",
				},
				{
					Identifier: "common-components/web-service",
				},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/http-endpoint",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/web-service",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("http-endpoint/%s", idSafe),
		},
	}

	// Process each policy path using the policy manager
	p.logger.Debug("Processing policies", "count", len(req.GetPolicyPaths()))

	for _, policyPath := range req.GetPolicyPaths() {
		processor := policyManager.NewPolicyProcessor(
			p.logger,
			map[string]string{
				"provider": "http",
				"type":     "endpoint",
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)

		// Process headers using helper function
		headersMap := processHeaders(responseData.Headers)

		dataMap := map[string]interface{}{
			"status_code":        responseData.StatusCode,
			"status":             responseData.Status,
			"headers":            headersMap, // Nested structure for policies
			"body":               responseData.Body,
			"response_time_ms":   responseData.ResponseTime,
			"success":            responseData.Success,
			"error":              responseData.Error,
			"matched_regex":      responseData.MatchedRegex,
			"body_regex_pattern": responseData.BodyRegexPattern,
		}

		// Pass the flat map to policy manager (like SSH plugin does)
		evidence, err := processor.GenerateResults(ctx, policyPath, dataMap)
		evidences = append(evidences, evidence...)
		if err != nil {
			// Wrap error with policy context for better debugging
			wrappedErr := fmt.Errorf("policy evaluation failed for '%s': %w", policyPath, err)
			accumulatedErrors = errors.Join(accumulatedErrors, wrappedErr)
		}
	}

	p.logger.Debug("Successfully generated evidence", "count", len(evidences))
	return evidences, accumulatedErrors
}


// Eval implements runner.Runner
// This is the main execution function where we make HTTP requests and evaluate policies
func (p *HttpCollectorPlugin) Eval(req *proto.EvalRequest, helper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	p.logger.Debug("Starting HTTP evaluation")

	// Make HTTP request and collect data
	responseData, err := p.makeHttpRequest()
	if err != nil {
		p.logger.Error("HTTP request failed", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	// Evaluate policies against HTTP response data
	evidences, err := p.EvaluatePolicies(ctx, responseData, req)
	if err != nil {
		p.logger.Error("Error evaluating policies", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	// Enhance evidence with comprehensive HTTP metrics before storing in database
	p.enhanceEvidenceWithHttpData(evidences, responseData)

	// Send policy-based evidences to the compliance API
	if err := helper.CreateEvidence(ctx, evidences); err != nil {
		p.logger.Error("Failed to send evidence", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	p.logger.Info("HTTP evaluation completed successfully",
		"success", responseData.Success,
		"evidence_count", len(evidences),
		"response_time_ms", responseData.ResponseTime)

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func main() {
	// Create logger for the plugin
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "http-collector-plugin",
		Output: hclog.DefaultOutput,
		Level:  hclog.Debug,
	})

	// Serve the plugin using HashiCorp's plugin framework
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]plugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: &HttpCollectorPlugin{
					logger: logger,
				},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}