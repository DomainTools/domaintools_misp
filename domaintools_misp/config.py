IRIS_DETECT_USER_CONFIG = {
    "api_endpoint": {
        "type": "Select",
        "message": """
            Import newly discovered domains that need analysis (new) or only those domains that have been manually selected to be “watched”.
            See the Iris Detect User Guide (https://www.domaintools.com/wp-content/uploads/DomainTools_Iris_Detect_User_Guide.pdf) for more information. """,
        "options": ["new", "watched"],
    },
    "test_mode": {
        "type": "Boolean",
        "message": "To help with testing and configuration, you can limit the API response to 10 results and not be limited by hourly restrictions.",
    },
    "monitor_id": {
        "type": "String",
        "message": """
            Enter the monitor ID (e.g. eXj3g7XmJq) corresponding to the monitored term you would like to import, or leave blank to import domains associated with all monitors.
            You can get the monitor ID from Iris Detect UI (https://iris.domaintools.com/detect/). Select Settings -> Show API IDs for monitors and domains.""",
        "validation": "0",
    },
    "risk_score_ranges": {
        "type": "Select",
        "message": "Filters on domains with a risk score in different ranges.",
        "options": ["None", "0-0", "1-39", "40-69", "70-99", "100-100"],
    },
    "discovered_date": {
        "type": "String",
        "errorMessage": "Wrong date format",
        "message": """
            Most relevant for the "watched" endpoint to control the timeframe for changes to DNS or Whois fields for watched domains.
            Examples: 2022-02-28 or 2022-02-28T01:23:45+00:00. Leave blank to import the 100 most recent domains matching your search criteria.""",
        "validation": "0",
    },
    "changed_since": {
        "type": "String",
        "errorMessage": "Wrong date format",
        "message": """
            Most relevant for the "new" endpoint to control the timeframe for when a new domain was discovered.
            Examples: 2022-02-28 or 2022-02-28T01:23:45+00:00. Leave blank to import the 100 most recent domains matching your search criteria.""",
        "validation": "0",
    },
    "escalated_since": {
        "type": "String",
        "errorMessage": "Wrong date format",
        "message": """
            Most relevant for the "watched" endpoint to control the timeframe for when a domain was most recently escalated by your organization's team.
            Examples: 2022-02-28 or 2022-02-28T01:23:45+00:00. Leave blank to import the 100 most recent domains matching your search criteria.""",
        "validation": "0",
    },
    "escalation_types": {
        "type": "Select",
        "message": """
            When importing watched_domains, optionally specify whether you would like to import all watched domains,
            only those escalated to the blocklist API, or only those escalated to Google Safe Browsing.""",
        "options": ["All", "Blocklist API", "Google Safe Browsing"],
    },
    "tag_domains_as_blocked": {
        "type": "Boolean",
        "message": "If you check this box, mark domains to be blocked for internal use.",
    },
    "include_domain_data": {
        "type": "Boolean",
        "message": "Includes DNS (NS, MX, and IP) and Whois Details where known for each imported domain.",
    },
}
