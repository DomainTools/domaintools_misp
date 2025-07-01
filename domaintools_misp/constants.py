GUIDED_PIVOT_COUNT_MIN = 1
GUIDED_PIVOT_COUNT_MAX = 500

ATTRIBUTE_TYPES_MAP = {
    "email domain": "hostname",
    "ip address": "ip-dst",
    "mx host": "hostname",
    "mx domain": "hostname",
    "mx ip": "ip-dst",
    "name server host": "hostname",
    "name server domain": "hostname",
    "name server ip": "ip-dst",
}

ESCALATION_TYPES_MAP = {
    "0": None,
    "1": "blocked",
    "2": "google_safe",
}

RISK_SCORE_RANGES_MAP = {
    "0": None,
    "1": "0-0",
    "2": "1-39",
    "3": "40-69",
    "4": "70-99",
    "5": "100-100",
}

PIVOT_MAP = {
    "domain": "domain",
    "ip-src": "ip",
    "ip-dst": "ip",
    "whois-registrant-email": "email",
    "email-dst": "email",
    "email-src": "email",
    "hostname": "nameserver_host",
    "whois-registrar": "registrar",
    "whois-registrant-name": "registrant",
    "x509-fingerprint-sha1": "ssl_hash",
}
