package compliance_framework.http_collector.require_json_content

test_json_content_passes {
    count(violation) == 0 with input as {
        "headers": {
            "Content-Type": ["application/json"]
        }
    }
}

test_json_content_fails_with_html {
    count(violation) == 1 with input as {
        "headers": {
            "Content-Type": ["text/html"]
        }
    }
}