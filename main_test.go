package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/protobuf/types/known/structpb"
)

// testPolicies is a copy of the plugin-http-collector-policies bundle (see testdata/README.md).
const testPolicies = "testdata/policies"

const (
	successStatusPolicy = "compliance_framework.http_collector.ensure_success_status"
	jsonContentPolicy   = "compliance_framework.http_collector.require_json_content"
	responseTimePolicy  = "compliance_framework.http_collector.response_time_check"
)

const (
	satisfied    = proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED
	notSatisfied = proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED
)

type fakeApiHelper struct {
	calls     int
	evidences []*proto.Evidence
	err       error
}

func (f *fakeApiHelper) CreateEvidence(_ context.Context, evidences []*proto.Evidence) error {
	f.calls++
	f.evidences = append(f.evidences, evidences...)
	return f.err
}

func (f *fakeApiHelper) UpsertRiskTemplates(context.Context, string, []*proto.RiskTemplate) error {
	return nil
}

func (f *fakeApiHelper) UpsertSubjectTemplates(context.Context, []*proto.SubjectTemplate) error {
	return nil
}

func newConfiguredPlugin(t *testing.T, config map[string]string) *HttpCollectorPlugin {
	t.Helper()
	p := &HttpCollectorPlugin{logger: hclog.NewNullLogger()}
	if _, err := p.Configure(&proto.ConfigureRequest{Config: config}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

// fakeClock returns start on its first call and start+elapsed on every later one, so the
// measured response time is elapsed.
func fakeClock(elapsed time.Duration) func() time.Time {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	calls := 0
	return func() time.Time {
		calls++
		if calls == 1 {
			return start
		}
		return start.Add(elapsed)
	}
}

// serve returns a test server answering every request with status, the given Content-Type
// (none at all when contentType is empty) and a small body.
func serve(t *testing.T, status int, contentType string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType == "" {
			w.Header()["Content-Type"] = nil // stop net/http sniffing one
		} else {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func byPolicy(t *testing.T, evidences []*proto.Evidence) map[string]*proto.Evidence {
	t.Helper()
	out := map[string]*proto.Evidence{}
	for _, evidence := range evidences {
		policy := evidence.GetLabels()["_policy"]
		if _, dup := out[policy]; dup {
			t.Fatalf("two evidences for policy %q", policy)
		}
		out[policy] = evidence
	}
	return out
}

func props(evidence *proto.Evidence) map[string]string {
	out := map[string]string{}
	for _, prop := range evidence.GetProps() {
		out[prop.GetName()] = prop.GetValue()
	}
	return out
}

func assertStates(t *testing.T, evidences []*proto.Evidence, want map[string]proto.EvidenceStatusState) {
	t.Helper()
	got := byPolicy(t, evidences)
	if len(got) != len(want) {
		t.Fatalf("got evidence for %d policies, want %d: %v", len(got), len(want), got)
	}
	for policy, state := range want {
		evidence, ok := got[policy]
		if !ok {
			t.Fatalf("no evidence for policy %q", policy)
		}
		if evidence.GetStatus().GetState() != state {
			t.Errorf("policy %q: state %v, want %v", policy, evidence.GetStatus().GetState(), state)
		}
	}
}

func TestEvalPolicyOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		elapsed     time.Duration
		want        map[string]proto.EvidenceStatusState
	}{
		{
			name: "all policies pass", status: http.StatusOK, contentType: "application/json", elapsed: 150 * time.Millisecond,
			want: map[string]proto.EvidenceStatusState{successStatusPolicy: satisfied, jsonContentPolicy: satisfied, responseTimePolicy: satisfied},
		},
		{
			name: "non-2xx status violates ensure_success_status", status: http.StatusInternalServerError, contentType: "application/json", elapsed: 150 * time.Millisecond,
			want: map[string]proto.EvidenceStatusState{successStatusPolicy: notSatisfied, jsonContentPolicy: satisfied, responseTimePolicy: satisfied},
		},
		{
			name: "JSON with a charset passes require_json_content", status: http.StatusCreated, contentType: "application/json; charset=utf-8", elapsed: 150 * time.Millisecond,
			want: map[string]proto.EvidenceStatusState{successStatusPolicy: satisfied, jsonContentPolicy: satisfied, responseTimePolicy: satisfied},
		},
		{
			name: "HTML violates require_json_content", status: http.StatusOK, contentType: "text/html", elapsed: 150 * time.Millisecond,
			want: map[string]proto.EvidenceStatusState{successStatusPolicy: satisfied, jsonContentPolicy: notSatisfied, responseTimePolicy: satisfied},
		},
		{
			name: "missing Content-Type violates require_json_content", status: http.StatusOK, contentType: "", elapsed: 150 * time.Millisecond,
			want: map[string]proto.EvidenceStatusState{successStatusPolicy: satisfied, jsonContentPolicy: notSatisfied, responseTimePolicy: satisfied},
		},
		{
			name: "5000 ms passes response_time_check", status: http.StatusOK, contentType: "application/json", elapsed: 5000 * time.Millisecond,
			want: map[string]proto.EvidenceStatusState{successStatusPolicy: satisfied, jsonContentPolicy: satisfied, responseTimePolicy: satisfied},
		},
		{
			name: "slow response violates response_time_check", status: http.StatusOK, contentType: "application/json", elapsed: 6 * time.Second,
			want: map[string]proto.EvidenceStatusState{successStatusPolicy: satisfied, jsonContentPolicy: satisfied, responseTimePolicy: notSatisfied},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := serve(t, tt.status, tt.contentType)
			p := newConfiguredPlugin(t, map[string]string{"url": srv.URL})
			p.now = fakeClock(tt.elapsed)
			helper := &fakeApiHelper{}

			resp, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{testPolicies}}, helper)
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			if resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
				t.Fatalf("Eval status %v, want SUCCESS", resp.GetStatus())
			}
			if helper.calls != 1 {
				t.Fatalf("CreateEvidence called %d times, want 1", helper.calls)
			}
			assertStates(t, helper.evidences, tt.want)
		})
	}
}

func TestEvalEvidenceShape(t *testing.T) {
	srv := serve(t, http.StatusOK, "application/json")
	config := map[string]string{"url": srv.URL, "method": "get", "body_regex_pattern": `"status":"ok"`}

	run := func() []*proto.Evidence {
		p := newConfiguredPlugin(t, config)
		p.now = fakeClock(150 * time.Millisecond)
		helper := &fakeApiHelper{}
		if _, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{testPolicies}}, helper); err != nil {
			t.Fatalf("Eval: %v", err)
		}
		return helper.evidences
	}
	first, second := byPolicy(t, run()), byPolicy(t, run())

	evidence := first[successStatusPolicy]
	if evidence == nil {
		t.Fatalf("no evidence for %s", successStatusPolicy)
	}

	labels := evidence.GetLabels()
	for key, want := range map[string]string{"provider": "http", "url": srv.URL, "method": "GET", "severity": "high"} {
		if labels[key] != want {
			t.Errorf("label %q = %q, want %q", key, labels[key], want)
		}
	}

	gotProps := props(evidence)
	for key, want := range map[string]string{
		"http_url": srv.URL, "http_method": "GET", "status_code": "200", "response_time_ms": "150",
		"success": "true", "regex_pattern": `"status":"ok"`, "regex_matched": "true",
	} {
		if gotProps[key] != want {
			t.Errorf("prop %q = %q, want %q", key, gotProps[key], want)
		}
	}
	if _, ok := gotProps["error"]; ok {
		t.Errorf("unexpected error prop on a successful request: %q", gotProps["error"])
	}

	if len(evidence.GetActivities()) == 0 || evidence.GetActivities()[0].GetTitle() != "HTTP Health Check" {
		t.Errorf("first activity is not the HTTP health check: %v", evidence.GetActivities())
	}
	if len(evidence.GetSubjects()) != 1 || evidence.GetSubjects()[0].GetIdentifier() != srv.URL {
		t.Errorf("subjects = %v, want the URL", evidence.GetSubjects())
	}
	if got := evidence.GetEnd().AsTime().Sub(evidence.GetStart().AsTime()); got != 150*time.Millisecond {
		t.Errorf("evidence spans %v, want the request's 150ms", got)
	}

	var input map[string]interface{}
	if err := json.Unmarshal(evidence.GetPolicyEvaluation().GetInput(), &input); err != nil {
		t.Fatalf("policy input is not JSON: %v", err)
	}
	if input["status_code"] != float64(200) || input["success"] != true || input["response_time_ms"] != float64(150) {
		t.Errorf("policy input = %v", input)
	}
	if input["body"] != `{"status":"ok"}` {
		t.Errorf("policy input body = %v", input["body"])
	}
	headers, _ := input["headers"].(map[string]interface{})
	contentType, _ := headers["Content-Type"].([]interface{})
	if len(contentType) != 1 || contentType[0] != "application/json" {
		t.Errorf("policy input headers = %v, want Content-Type [application/json]", input["headers"])
	}

	for policy, evidence := range first {
		if evidence.GetUUID() == "" || evidence.GetUUID() != second[policy].GetUUID() {
			t.Errorf("policy %q: evidence UUID %q then %q, want the same non-empty UUID on every run",
				policy, evidence.GetUUID(), second[policy].GetUUID())
		}
	}
}

func TestEvalRequestFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens on url any more

	p := newConfiguredPlugin(t, map[string]string{"url": url})
	p.now = fakeClock(10 * time.Millisecond)
	helper := &fakeApiHelper{}

	resp, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{testPolicies}}, helper)
	if err == nil {
		t.Fatal("Eval returned no error for a failed request")
	}
	if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
		t.Fatalf("Eval status %v, want FAILURE", resp.GetStatus())
	}

	// The failure is still recorded as evidence: no 2xx and no JSON content.
	assertStates(t, helper.evidences, map[string]proto.EvidenceStatusState{
		successStatusPolicy: notSatisfied,
		jsonContentPolicy:   notSatisfied,
		responseTimePolicy:  satisfied,
	})
	gotProps := props(helper.evidences[0])
	if gotProps["success"] != "false" || gotProps["status_code"] != "0" || gotProps["error"] == "" {
		t.Errorf("props = %v, want success=false, status_code=0 and the error", gotProps)
	}
}

func TestEvalWithoutPolicies(t *testing.T) {
	srv := serve(t, http.StatusOK, "application/json")
	p := newConfiguredPlugin(t, map[string]string{"url": srv.URL})
	helper := &fakeApiHelper{}

	resp, err := p.Eval(&proto.EvalRequest{}, helper)
	if err != nil || resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
		t.Fatalf("Eval = %v, %v; want SUCCESS", resp.GetStatus(), err)
	}
	if helper.calls != 0 {
		t.Errorf("CreateEvidence called %d times without policies, want 0", helper.calls)
	}
}

func TestEvalInvalidPolicyPath(t *testing.T) {
	srv := serve(t, http.StatusOK, "application/json")
	p := newConfiguredPlugin(t, map[string]string{"url": srv.URL})
	helper := &fakeApiHelper{}

	resp, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{"testdata/does-not-exist"}}, helper)
	if err == nil || resp.GetStatus() != proto.ExecutionStatus_FAILURE {
		t.Fatalf("Eval = %v, %v; want FAILURE with an error", resp.GetStatus(), err)
	}
	if helper.calls != 0 {
		t.Errorf("CreateEvidence called %d times after a policy error, want 0", helper.calls)
	}
}

func TestEvalCreateEvidenceError(t *testing.T) {
	srv := serve(t, http.StatusOK, "application/json")
	p := newConfiguredPlugin(t, map[string]string{"url": srv.URL})
	sendErr := errors.New("api unavailable")
	helper := &fakeApiHelper{err: sendErr}

	resp, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{testPolicies}}, helper)
	if !errors.Is(err, sendErr) || resp.GetStatus() != proto.ExecutionStatus_FAILURE {
		t.Fatalf("Eval = %v, %v; want FAILURE with the send error", resp.GetStatus(), err)
	}
}

func TestEvalNotConfigured(t *testing.T) {
	p := &HttpCollectorPlugin{logger: hclog.NewNullLogger()}
	resp, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{testPolicies}}, &fakeApiHelper{})
	if err == nil || resp.GetStatus() != proto.ExecutionStatus_FAILURE {
		t.Fatalf("Eval = %v, %v; want FAILURE with an error", resp.GetStatus(), err)
	}
}

func TestConfigureStoresPolicyData(t *testing.T) {
	policyData, err := structpb.NewStruct(map[string]interface{}{"max_response_time_ms": 2000})
	if err != nil {
		t.Fatal(err)
	}
	p := &HttpCollectorPlugin{logger: hclog.NewNullLogger()}

	if _, err := p.Configure(&proto.ConfigureRequest{Config: map[string]string{"url": "http://example.test"}, PolicyData: policyData}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if p.policyData["max_response_time_ms"] != float64(2000) {
		t.Fatalf("policyData = %v, want max_response_time_ms=2000", p.policyData)
	}

	if _, err := p.Configure(&proto.ConfigureRequest{Config: map[string]string{"url": "http://example.test"}}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if p.policyData != nil {
		t.Fatalf("policyData = %v after a Configure without policy_data, want nil", p.policyData)
	}
}

func TestEvalPassesPolicyData(t *testing.T) {
	srv := serve(t, http.StatusOK, "application/json")
	policyData, err := structpb.NewStruct(map[string]interface{}{"max_response_time_ms": 2000})
	if err != nil {
		t.Fatal(err)
	}
	p := &HttpCollectorPlugin{logger: hclog.NewNullLogger()}
	if _, err := p.Configure(&proto.ConfigureRequest{Config: map[string]string{"url": srv.URL}, PolicyData: policyData}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	helper := &fakeApiHelper{}
	if _, err := p.Eval(&proto.EvalRequest{PolicyPaths: []string{testPolicies}}, helper); err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if len(helper.evidences) == 0 {
		t.Fatal("no evidence")
	}
	for _, evidence := range helper.evidences {
		if got := string(evidence.GetPolicyEvaluation().GetPolicyData()); got != `{"max_response_time_ms":2000}` {
			t.Errorf("policy data recorded for %s = %s", evidence.GetLabels()["_policy"], got)
		}
	}
}
