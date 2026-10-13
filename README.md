# Compliance Framework HTTP Collector Plugin

Fetches an HTTP endpoint and evaluates the configured policies against the response, for health monitoring and
compliance validation.

This plugin is intended to be run as part of an agent to validate HTTP endpoints against defined compliance policies.

## Policies

The plugin evaluates the policy bundles listed under `policies` in the agent's plugin config, usually the
[plugin-http-collector-policies](https://github.com/compliance-framework/plugin-http-collector-policies) bundle:

```yaml
plugins:
  health-checker:
    source: ghcr.io/compliance-framework/plugin-http-collector:<version>
    policies:
      - ghcr.io/compliance-framework/plugin-http-collector-policies:<version>
    config:
      url: https://example.com/health
```

Each run makes one request and evaluates every policy package in every bundle against it, producing one evidence
per package. Without `policies` the plugin makes the request but produces no evidence.

Policies are Rego v1 and live under the `compliance_framework.http_collector` package. They report failures with
a `violation` set, and set `title`, `description` and optionally `labels` (merged into the evidence labels):

```rego
package compliance_framework.http_collector.ensure_success_status

import rego.v1

violation contains {} if {
	not input.success
}

title := "HTTP endpoint should return successful status codes"
description := "HTTP endpoints should return 2xx status codes to ensure proper service functionality"
labels := {"severity": "high"}
```

### Policy input

The input is the response, as JSON:

```json
{
  "status_code": 200,
  "status": "200 OK",
  "headers": {
    "Content-Type": ["application/json"],
    "Content-Length": ["1234"]
  },
  "body": "response body content",
  "response_time_ms": 150,
  "success": true,
  "error": "error message if request failed",
  "matched_regex": true,
  "body_regex_pattern": "pattern used for matching"
}
```

- `headers` uses Go's canonical header names (`Content-Type`), each with a list of values.
- `success` is true for a 2xx status.
- `error` is set only when no response was received (the request could not be built or sent, or the body could
  not be read). Then `success` is false, `status_code` is 0 (unless the body read failed), and the plugin still
  evaluates the policies, so the failure is recorded as evidence, before `Eval` reports `FAILURE`.
- `matched_regex` and `body_regex_pattern` are set only when `body_regex_pattern` is configured
  (`matched_regex` is left out when false).

### Policy data

`policy_data` from the agent config is passed to the policies as `data`.

### Evidence

Each evidence carries:

- labels `provider: http`, `url` and `method` (with the policy's `_policy` and its own `labels`). Together with
  the policy they derive the evidence UUID, so the same endpoint and policy keep one evidence history across runs;
- props `http_url`, `http_method`, `status_code`, `response_time_ms` and `success`, plus `error` when the request
  failed and `regex_pattern` and `regex_matched` when `body_regex_pattern` is configured;
- the `HTTP Health Check` activity (client settings, request, response size and time), followed by the policy
  manager's activities;
- the endpoint URL as a component subject, and start and end times of the request.

The response itself (the policy input above) is recorded with the evidence's policy evaluation.

## Configuration

The plugin supports the following configuration options:

- `url` (required): The HTTP endpoint URL to test
- `method`: HTTP method to use (default: "GET") 
- `timeout`: Request timeout in milliseconds (default: 5000)
- `basic_auth`: Enable basic authentication (default: false)
- `basic_auth_username`: Username for basic auth
- `basic_auth_password`: Password for basic auth
- `additional_headers`: Additional headers in format "Key1: Value1;Key2: Value2"
- `check_certificate`: Validate SSL certificates (default: true)
- `body_regex_pattern`: Regex pattern to match against response body

## Releases

This plugin is released using goreleaser to build binaries, and Docker to build OCI artifacts, 
which will ensure a binary is built for most OS and Architecture combinations. 

You can find the binaries on each release of this plugin in the GitHub releases page.

You can find the OCI implementations in the GitHub Packages page.