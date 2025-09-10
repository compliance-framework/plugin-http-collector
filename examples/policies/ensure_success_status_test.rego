package compliance_framework.http_collector.ensure_success_status

test_success_status_passes {
    count(violation) == 0 with input as {
        "status_code": 200,
        "success": true
    }
}

test_success_status_fails_for_error {
    count(violation) == 1 with input as {
        "status_code": 500,
        "success": false
    }
}