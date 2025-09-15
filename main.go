package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/mitchellh/mapstructure"
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

// HttpResponseData represents the structured response data
// This will be converted to JSON and included in evidence
type HttpResponseData struct {
	StatusCode       int                 `json:"status_code"`
	Status           string              `json:"status"`
	Headers          map[string][]string `json:"headers"`
	Body             string              `json:"body"`
	ResponseTime     int64               `json:"response_time_ms"`
	Success          bool                `json:"success"`                      // true if 200 <= status < 300
	Error            string              `json:"error,omitempty"`              // only if request failed
	MatchedRegex     bool                `json:"matched_regex,omitempty"`      // only if regex pattern provided
	BodyRegexPattern string              `json:"body_regex_pattern,omitempty"` // echo back the pattern used
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

	// Use mapstructure for better config parsing
	if err := mapstructure.Decode(req.Config, config); err != nil {
		p.logger.Error("Error decoding config", "error", err)
		return nil, err
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

// makeHttpRequest performs the HTTP request and returns structured response data
func (p *HttpCollectorPlugin) makeHttpRequest() (*HttpResponseData, error) {
	startTime := time.Now()

	// Create HTTP client with timeout and TLS settings
	client := &http.Client{
		Timeout: time.Duration(p.config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !p.config.CheckCertificate,
			},
		},
	}

	// Create HTTP request
	req, err := http.NewRequest(p.config.Method, p.config.URL, nil)
	if err != nil {
		return &HttpResponseData{
			Success: false,
			Error:   fmt.Sprintf("failed to create request: %v", err),
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

	// Execute the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return &HttpResponseData{
			Success:      false,
			Error:        fmt.Sprintf("HTTP request failed: %v", err),
			ResponseTime: time.Since(startTime).Milliseconds(),
		}, nil
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &HttpResponseData{
			Success:      false,
			Error:        fmt.Sprintf("failed to read response body: %v", err),
			StatusCode:   resp.StatusCode,
			Status:       resp.Status,
			Headers:      resp.Header,
			ResponseTime: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Check if status code indicates success (200 <= x < 300)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	responseData := &HttpResponseData{
		StatusCode:   resp.StatusCode,
		Status:       resp.Status,
		Headers:      resp.Header,
		Body:         string(body),
		Success:      success,
		ResponseTime: time.Since(startTime).Milliseconds(),
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

	p.logger.Info("HTTP request completed",
		"status", resp.StatusCode,
		"success", success,
		"response_time_ms", responseData.ResponseTime)

	return responseData, nil
}

// EvaluatePolicies processes policies against HTTP response data using the policy manager
func (p *HttpCollectorPlugin) EvaluatePolicies(ctx context.Context, responseData *HttpResponseData, req *proto.EvalRequest) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	evidences := make([]*proto.Evidence, 0)

	// Add HTTP data collection activity
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
				Description: fmt.Sprintf("Received status %d, processed %d bytes in %dms", responseData.StatusCode, len(responseData.Body), responseData.ResponseTime),
			},
		},
	})

	// Get hostname for inventory identification
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	// Define origin actors
	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  policyManager.Pointer("reference"),
					Text: policyManager.Pointer("The Continuous Compliance Framework"),
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
					Text: policyManager.Pointer("The Continuous Compliance Framework HTTP Collector Plugin"),
				},
			},
		},
	}

	// Define components with proper OSCAL modeling
	components := []*proto.Component{
		{
			Identifier:  "common-components/http-endpoint",
			Type:        "service",
			Title:       "HTTP Endpoint",
			Description: "HTTP service endpoint providing API or web services functionality. This component handles HTTP requests and responses, enforcing security policies and performance requirements.",
			Purpose:     "Serve HTTP requests and provide application functionality with appropriate security, performance, and availability controls.",
			Protocols: []*proto.Protocol{
				{
					UUID:  "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
					Name:  "HTTP",
					Title: "HyperText Transfer Protocol",
					PortRanges: []*proto.PortRange{
						{
							End:       80,
							Start:     80,
							Transport: "TCP",
						},
					},
				},
				{
					UUID:  "B2C3D4E5-F6G7-8901-BCDE-F23456789012",
					Name:  "HTTPS",
					Title: "HTTP Secure",
					PortRanges: []*proto.PortRange{
						{
							End:       443,
							Start:     443,
							Transport: "TCP",
						},
					},
				},
			},
		},
	}

	// Define inventory items
	inventory := []*proto.InventoryItem{
		{
			Identifier: fmt.Sprintf("http-endpoint/%s", p.config.URL),
			Type:       "service",
			Title:      fmt.Sprintf("HTTP Endpoint [%s]", p.config.URL),
			Props: []*proto.Property{
				{
					Name:    "url",
					Value:   p.config.URL,
					Remarks: policyManager.Pointer("The target URL being monitored for compliance"),
				},
				{
					Name:    "method",
					Value:   p.config.Method,
					Remarks: policyManager.Pointer("The HTTP method used for health checks"),
				},
				{
					Name:    "hostname",
					Value:   hostname,
					Remarks: policyManager.Pointer("The hostname where the HTTP collector plugin is executed"),
				},
			},
			Links: []*proto.Link{
				{
					Href: p.config.URL,
					Text: policyManager.Pointer("Monitored Endpoint URL"),
				},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{
					Identifier: "common-components/http-endpoint",
				},
			},
		},
	}

	// Define subjects for policy evaluation
	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: "common-components/http-endpoint",
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: fmt.Sprintf("http-endpoint/%s", p.config.URL),
		},
	}

	// Process each policy path using the policy manager
	for _, policyPath := range req.GetPolicyPaths() {
		processor := policyManager.NewPolicyProcessor(
			p.logger,
			map[string]string{
				"provider":     "http",
				"type":         "endpoint",
				"url":          p.config.URL,
				"method":       p.config.Method,
				"hostname":     hostname,
				"_policy_path": policyPath,
			},
			subjects,
			components,
			inventory,
			actors,
			activities,
		)

		// Generate policy-based evidence
		evidence, err := processor.GenerateResults(ctx, policyPath, responseData)
		evidences = slices.Concat(evidences, evidence)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, err)
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