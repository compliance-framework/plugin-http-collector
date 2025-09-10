# Compliance Framework HTTP Collector Plugin

Fetches HTTP endpoints and runs passed policies against the response data for health monitoring and compliance validation.

This plugin is intended to be run as part of an agent to validate HTTP endpoints against defined compliance policies.

## Policies

When writing OPA / Rego policies for this plugin, they must be added under the `compliance_framework.http_collector`
rego module:

```rego
# ensure_https.rego
# package compliance_framework.http_collector.[YOUR_RULE_PATH]
package compliance_framework.http_collector.ensure_https
```

The plugin expects Rego policies to output a `violation` key to indicate failed resources, which will be reported to the 
compliance framework. Additional data can be added to violations, that describe what failed, and recommendations on how 
to fix them.

Here is an example rego policy which ensures that endpoints return successful HTTP status codes:

```rego
# ensure_success_status.rego
package compliance_framework.http_collector.ensure_success_status

import future.keywords.in

violation[{
    # Title describes the violation
    "title": "HTTP endpoint returned non-success status code.",
    # Description adds more details about the violation
    "description": "HTTP endpoints should return 2xx status codes to indicate successful responses.",
    # Remarks indicate how this can be fixed or remediated
    "remarks": "Check the endpoint configuration and ensure the service is running properly."
}] {
	input.success == false
}
```

## Response Data Structure

The plugin provides the following data structure to policies:

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