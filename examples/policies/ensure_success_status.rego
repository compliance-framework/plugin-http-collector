package compliance_framework.http_collector.ensure_success_status

import future.keywords.in

violation[{}] if {
	input.success == false
}

title := "HTTP endpoint returned non-success status code"
description := "HTTP endpoints should return 2xx status codes to indicate successful responses"
remarks := "Check the endpoint configuration and ensure the service is running properly"