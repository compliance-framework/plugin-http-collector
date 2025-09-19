package compliance_framework.http_collector.require_json_content

import future.keywords.in

violation[{}] if {
	not input.headers["Content-Type"]
}

violation[{}] if {
	input.headers["Content-Type"]
	count([ct | ct := input.headers["Content-Type"][_]; contains(ct, "application/json")]) == 0
}

title := "HTTP endpoint does not return JSON content"
description := "API endpoints should return JSON content type for proper client compatibility"
remarks := "Configure the service to return 'application/json' content type header"