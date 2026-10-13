package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
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

// HttpResponseData represents the structured response data.
// Its JSON form is the input the policies evaluate (see README).
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

	// When the request started and ended; not part of the policy input.
	startedAt time.Time
	endedAt   time.Time
}

var _ runner.RunnerV2 = (*HttpCollectorPlugin)(nil)

// HttpCollectorPlugin implements the RunnerV2 interface
type HttpCollectorPlugin struct {
	logger     hclog.Logger
	config     *HttpCollectorConfig
	policyData map[string]interface{}
	now        func() time.Time // nil means time.Now
}

// Configure implements runner.Runner
// This is called by the agent to provide configuration to the plugin
func (p *HttpCollectorPlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	p.logger.Debug("Configuring HTTP collector plugin")

	// Initialize with defaults
	config := &HttpCollectorConfig{
		Method:           "GET",
		Timeout:          5000,
		CheckCertificate: true, // default to secure
	}

	// Parse configuration from the agent
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

	// Validate required configuration
	if config.URL == "" {
		return nil, fmt.Errorf("url is required in configuration")
	}

	p.config = config
	// policy_data from the agent config, passed to the policies as data (nil when unset).
	p.policyData = nil
	if policyData := req.GetPolicyData(); policyData != nil {
		p.policyData = policyData.AsMap()
	}
	p.logger.Info("HTTP collector configured successfully",
		"url", config.URL,
		"method", config.Method,
		"timeout", config.Timeout)

	return &proto.ConfigureResponse{}, nil
}

// clock returns the time source used to measure the request; tests replace it.
func (p *HttpCollectorPlugin) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// makeHttpRequest performs the HTTP request and returns structured response data.
// The data is never nil. When no response was received (the request could not be built
// or sent, or its body could not be read), the data carries success=false and the error,
// and the error is returned too.
func (p *HttpCollectorPlugin) makeHttpRequest(ctx context.Context) (*HttpResponseData, error) {
	startTime := p.clock()
	fail := func(data *HttpResponseData, err error) (*HttpResponseData, error) {
		endTime := p.clock()
		data.Success = false
		data.Error = err.Error()
		data.ResponseTime = endTime.Sub(startTime).Milliseconds()
		data.startedAt, data.endedAt = startTime, endTime
		return data, err
	}

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
	req, err := http.NewRequestWithContext(ctx, p.config.Method, p.config.URL, nil)
	if err != nil {
		return fail(&HttpResponseData{}, fmt.Errorf("failed to create request: %w", err))
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
		return fail(&HttpResponseData{}, fmt.Errorf("HTTP request failed: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail(&HttpResponseData{
			StatusCode: resp.StatusCode,
			Status:     resp.Status,
			Headers:    resp.Header,
		}, fmt.Errorf("failed to read response body: %w", err))
	}
	endTime := p.clock()

	// Check if status code indicates success (200 <= x < 300)
	success := resp.StatusCode >= 200 && resp.StatusCode < 300

	responseData := &HttpResponseData{
		StatusCode:   resp.StatusCode,
		Status:       resp.Status,
		Headers:      resp.Header,
		Body:         string(body),
		Success:      success,
		ResponseTime: endTime.Sub(startTime).Milliseconds(),
		startedAt:    startTime,
		endedAt:      endTime,
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

// labels identify the checked endpoint. With the policy package, they seed the evidence
// UUID (policy_manager), so they must stay the same between runs of one configuration.
func (p *HttpCollectorPlugin) labels() map[string]string {
	return map[string]string{
		"provider": "http",
		"url":      p.config.URL,
		"method":   p.config.Method,
	}
}

// responseProps are the properties the plugin's hand-built evidence carried before it
// evaluated policies. They are added to every evidence the policies produce.
func (p *HttpCollectorPlugin) responseProps(responseData *HttpResponseData) []*proto.Property {
	props := []*proto.Property{
		{Name: "http_url", Value: p.config.URL},
		{Name: "http_method", Value: p.config.Method},
		{Name: "status_code", Value: strconv.Itoa(responseData.StatusCode)},
		{Name: "response_time_ms", Value: strconv.FormatInt(responseData.ResponseTime, 10)},
		{Name: "success", Value: strconv.FormatBool(responseData.Success)},
	}
	if responseData.Error != "" {
		props = append(props, &proto.Property{Name: "error", Value: responseData.Error})
	}
	if responseData.BodyRegexPattern != "" {
		props = append(props,
			&proto.Property{Name: "regex_pattern", Value: responseData.BodyRegexPattern},
			&proto.Property{Name: "regex_matched", Value: strconv.FormatBool(responseData.MatchedRegex)},
		)
	}
	return props
}

// activities describe how the response was collected; policy_manager appends its own
// policy execution activities after them.
func (p *HttpCollectorPlugin) activities(responseData *HttpResponseData) []*proto.Activity {
	return []*proto.Activity{
		{
			Title:       "HTTP Health Check",
			Description: fmt.Sprintf("Performed %s request to %s for health monitoring", p.config.Method, p.config.URL),
			Steps: []*proto.Step{
				{
					Title: "Configure HTTP Client",
					Description: fmt.Sprintf("Set timeout: %dms, certificate check: %t, basic auth: %t",
						p.config.Timeout, p.config.CheckCertificate, p.config.BasicAuth),
				},
				{
					Title:       "Execute HTTP Request",
					Description: fmt.Sprintf("Made %s request to %s", p.config.Method, p.config.URL),
				},
				{
					Title: "Process Response",
					Description: fmt.Sprintf("Received status %d, processed %d bytes in %dms",
						responseData.StatusCode, len(responseData.Body), responseData.ResponseTime),
				},
			},
		},
	}
}

// EvalPolicies evaluates every policy path against the response data and returns the
// resulting evidence. The policy input is the response data as JSON (see README).
func (p *HttpCollectorPlugin) EvalPolicies(ctx context.Context, responseData *HttpResponseData, policyPaths []string) ([]*proto.Evidence, error) {
	var accumulatedErrors error
	evidences := make([]*proto.Evidence, 0)

	subjects := []*proto.Subject{
		{
			Identifier:  p.config.URL,
			Type:        proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Description: fmt.Sprintf("HTTP endpoint at %s", p.config.URL),
		},
	}
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
	activities := p.activities(responseData)

	for _, policyPath := range policyPaths {
		processor := policyManager.NewPolicyProcessor(
			p.logger,
			p.labels(),
			subjects,
			nil,
			nil,
			actors,
			activities,
			p.policyData,
		)

		results, err := processor.GenerateResults(ctx, policyPath, responseData)
		if err != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, fmt.Errorf("evaluate policies in %s: %w", policyPath, err))
		}
		evidences = append(evidences, results...)
	}

	for _, evidence := range evidences {
		// policy_manager sets the props to the violation IDs, so the response props are added after it.
		evidence.Props = append(evidence.Props, p.responseProps(responseData)...)
		evidence.Start = timestamppb.New(responseData.startedAt)
		evidence.End = timestamppb.New(responseData.endedAt)
	}

	return evidences, accumulatedErrors
}

// subjectTemplates are the subjects the plugin registers in Init: one HTTP endpoint per
// URL and method, matching the evidence labels.
func subjectTemplates() []*proto.SubjectTemplate {
	return []*proto.SubjectTemplate{
		{
			Name:                "http-endpoint",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "HTTP Endpoint: {{ .method }} {{ .url }}",
			DescriptionTemplate: "HTTP endpoint {{ .url }} checked with {{ .method }}",
			PurposeTemplate:     "Represents an HTTP endpoint whose availability and response are checked",
			IdentityLabelKeys:   []string{"url", "method"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "url", Description: "The URL requested"},
				{Key: "method", Description: "The HTTP method used"},
			},
		},
	}
}

// Init implements runner.RunnerV2: it registers the subject templates and the risk
// templates of the configured policies.
func (p *HttpCollectorPlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	return runner.InitWithSubjectsAndRisksFromPolicies(context.Background(), p.logger, req, apiHelper, subjectTemplates())
}

// Eval implements runner.Runner.
// It requests the configured URL, evaluates the configured policies against the response
// and sends the resulting evidence to the API.
func (p *HttpCollectorPlugin) Eval(req *proto.EvalRequest, helper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()
	p.logger.Debug("Starting HTTP evaluation")

	if p.config == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.New("plugin is not configured")
	}

	// A request that got no response still produces input (success=false and the error),
	// so the policies record the endpoint as failing; Eval then reports FAILURE.
	responseData, requestErr := p.makeHttpRequest(ctx)
	if requestErr != nil {
		p.logger.Error("HTTP request failed", "error", requestErr)
	}

	if len(req.GetPolicyPaths()) == 0 {
		p.logger.Warn("No policies configured, so no evidence is produced")
	}

	evidences, err := p.EvalPolicies(ctx, responseData, req.GetPolicyPaths())
	if err != nil {
		p.logger.Error("Failed to evaluate policies", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.Join(requestErr, err)
	}

	if len(evidences) > 0 {
		if err := helper.CreateEvidence(ctx, evidences); err != nil {
			p.logger.Error("Failed to send evidence", "error", err)
			return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, errors.Join(requestErr, err)
		}
	}

	if requestErr != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, requestErr
	}

	p.logger.Info("HTTP evaluation completed successfully", "success", responseData.Success, "evidence", len(evidences))
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
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: &HttpCollectorPlugin{
					logger: logger,
				},
			},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
