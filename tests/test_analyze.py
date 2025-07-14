import json

from domaintools_misp.analyze import dt_misp_module_analyze


class TestAnalyze:
    def test_analyze_has_results(self, query_parameters):
        dtmm_analyze = dt_misp_module_analyze()
        response = dtmm_analyze.handler(json.dumps(query_parameters))
        assert "results" in response
        assert len(response["results"]) > 0

    def test_analyze_has_no_results_if_empty_query(self):
        dtmm_analyze = dt_misp_module_analyze()
        response = dtmm_analyze.handler()
        assert response == False

    def test_analyze_has_introspection(self, query_parameters):
        dtmm_analyze = dt_misp_module_analyze(json.dumps(query_parameters))
        assert dtmm_analyze.introspection() is not None

    def test_analyze_has_introspection_even_if_empty_query(self):
        dtmm_analyze = dt_misp_module_analyze()
        assert dtmm_analyze.introspection() is not None

    def test_analyze_has_version(self, version):
        dtmm_analyze = dt_misp_module_analyze()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                This module is superseded by the Iris Investigate module but remains here for backward compatibility.
                Optimized for MISP hover actions, the Analyze capability provides Whois data, a Domain Risk Score and counts of connected domains to help give quick context on an indicator to inform an interesting pivot and map connected infrastructure.
                Leverages the following DomainTools endpoints: Parsed Whois, Domain Profile, Risk, Reverse IP, Reverse Whois.
                """,
            "module-type": ["hover"],
            "config": ["username", "api_key", "results_limit"],
        }

        assert expected_version == dtmm_analyze.version()
