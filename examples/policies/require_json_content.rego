package compliance_framework.http_collector.require_json_content

import future.keywords.in

violation[{
    "title": "HTTP endpoint does not return JSON content.",
    "description": "API endpoints should return JSON content type for proper client compatibility.",
    "remarks": "Configure the service to return 'application/json' content type header."
}] {
	not "application/json" in input.headers["Content-Type"][_]
}