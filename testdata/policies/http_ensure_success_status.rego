package compliance_framework.http_collector.ensure_success_status

import rego.v1

violation contains {} if {
	not input.success
}

title := "HTTP endpoint should return successful status codes"
description := "HTTP endpoints should return 2xx status codes to ensure proper service functionality"
labels := {"severity": "high"}
