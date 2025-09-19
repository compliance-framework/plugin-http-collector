package compliance_framework.http_collector.response_time_check

violation[{}] if {
	input.response_time_ms > 5000
}

title := "HTTP response time exceeds acceptable threshold"
description := "HTTP endpoints should respond within reasonable time limits to ensure good user experience"
remarks := "Consider optimizing the backend service or reviewing network configuration"