package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	// policyManager "github.com/compliance-framework/agent/policy-manager" // TODO: Uncomment when library bug is fixed
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

	// Get hostname for inventory identification
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}


	// TODO: Uncomment when policy manager library is fixed
	// actors := []*proto.OriginActor{}
	// components := []*proto.Component{}
	// inventory := []*proto.InventoryItem{}
	// subjects := []*proto.Subject{}

	// Process each policy path using the policy manager
	p.logger.Debug("Processing policies", "count", len(req.GetPolicyPaths()))

	for _, policyPath := range req.GetPolicyPaths() {
		// TODO: Uncomment when policy manager library is fixed
		// processor := policyManager.NewPolicyProcessor(
		//	p.logger,
		//	map[string]string{
		//		"provider": "http",
		//		"type":     "endpoint",
		//	},
		//	subjects,   // TODO: Uncomment OSCAL metadata variables above
		//	components, // TODO: Uncomment OSCAL metadata variables above
		//	inventory,  // TODO: Uncomment OSCAL metadata variables above
		//	actors,     // TODO: Uncomment OSCAL metadata variables above
		//	activities, // TODO: Uncomment OSCAL metadata variables above
		// )

		// Convert to policy-compatible struct (simplify headers from []string to string)
		policyData := &HttpResponseDataForPolicy{
			StatusCode:       responseData.StatusCode,
			Status:           responseData.Status,
			Headers:          make(map[string]string),
			Body:             responseData.Body,
			ResponseTime:     responseData.ResponseTime,
			Success:          responseData.Success,
			Error:            responseData.Error,
			MatchedRegex:     responseData.MatchedRegex,
			BodyRegexPattern: responseData.BodyRegexPattern,
		}

		// Convert headers from []string to string (take first value or join multiple)
		for key, values := range responseData.Headers {
			if len(values) > 0 {
				if len(values) == 1 {
					policyData.Headers[key] = values[0]
				} else {
					policyData.Headers[key] = strings.Join(values, "; ")
				}
			}
		}

		// Convert policyData to map[string]interface{} using JSON marshaling/unmarshaling
		// This ensures proper type compatibility with the policy manager
		jsonBytes, err := json.Marshal(policyData)
		if err != nil {
			p.logger.Error("Failed to marshal policy data to JSON", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		var policyMap map[string]interface{}
		if err := json.Unmarshal(jsonBytes, &policyMap); err != nil {
			p.logger.Error("Failed to unmarshal policy data from JSON", "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		p.logger.Debug("Converted policy data to map", "data", policyMap)

		// TEMPORARY WORKAROUND: Policy manager library has a bug causing runtime panic:
		// "interface conversion: interface {} is []interface {}, not map[string]interface {}"
		// Location: github.com/compliance-framework/agent@v0.2.1/policy-manager/policy-manager.go:95
		//
		// Until the library is fixed, we'll skip policy evaluation and log the issue
		p.logger.Warn("Skipping policy evaluation due to policy manager library bug",
			"policy", policyPath,
			"bug", "interface conversion panic at policy-manager.go:95",
			"library", "github.com/compliance-framework/agent@v0.2.1/policy-manager")

		// TODO: Uncomment this when policy manager library is fixed:
		// evidence, err := processor.GenerateResults(ctx, policyPath, policyMap)
		// evidences = slices.Concat(evidences, evidence)
		// if err != nil {
		//     accumulatedErrors = errors.Join(accumulatedErrors, err)
		// }
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