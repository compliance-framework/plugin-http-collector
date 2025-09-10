package compliance_framework.http_collector.response_time_check

test_response_time_passes_under_threshold {
    count(violation) == 0 with input as {
        "response_time_ms": 1500
    }
}

test_response_time_fails_over_threshold {
    count(violation) == 1 with input as {
        "response_time_ms": 6000
    }
}