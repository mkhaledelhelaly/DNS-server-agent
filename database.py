dns_database = {
    "example.com": {
        "A": [
            {"value": "127.0.0.1", "ttl": 3600}
        ],
        "CNAME": [
            {"value": "www.example.com", "ttl": 3600}
        ],
        "MX": [
            {"value": "mail.example.com", "ttl": 3600, "priority": 10}  # Added priority
        ]
    },

    "anotherdomain.com": {
        "A": [
            {"value": "192.168.1.1", "ttl": 3600}
        ],
        "NS": [
            {"value": "ns1.anotherdomain.com", "ttl": 3600}
        ],
        "MX": [
            {"value": "mail.anotherdomain.com", "ttl": 3600, "priority": 20}  # Added priority
        ]
    },

    "google.com": {
        "A": [
            {"value": "142.250.190.78", "ttl": 300}
        ],
        "CNAME": [
            {"value": "www.google.com", "ttl": 300}
        ],
        "MX": [
            {"value": "alt1.google.com", "ttl": 300, "priority": 10},  # Added priority
            {"value": "alt2.google.com", "ttl": 300, "priority": 20}   # Added another MX with different priority
        ]
    },

    "wikipedia.org": {
        "A": [
            {"value": "208.80.154.224", "ttl": 300}
        ],
        "NS": [
            {"value": "ns1.wikipedia.org", "ttl": 300}
        ],
        "MX": [
            {"value": "mail.wikipedia.org", "ttl": 300, "priority": 5}  # Added priority
        ]
    }
}