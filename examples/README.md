# HTTP Collector Plugin Examples

This directory contains example configurations and policies for the HTTP Collector plugin.

## Structure

- `test-config.yaml`: Example agent configuration showing different HTTP collector scenarios
- `http_output/`: Sample HTTP response data structures
- `policies/`: Example Rego policies that can be applied to HTTP response data

## Running Examples

To test the plugin with the provided configuration:

1. Build the plugin:
   ```bash
   go build -o plugin-http-collector .
   ```

2. Run with the compliance agent using the example configuration:
   ```bash
   compliance-agent run --config examples/test-config.yaml
   ```

## Policy Examples

The example policies demonstrate common compliance checks:

- `ensure_success_status.rego`: Validates that HTTP responses have successful status codes
- `response_time_check.rego`: Ensures response times are within acceptable limits  
- `require_json_content.rego`: Validates that APIs return JSON content types

Each policy has a corresponding test file to validate the policy logic.