import json
import pytest

from domaintools_misp.pivot import dt_misp_module_pivot


@pytest.fixture
def dtmm_pivot_resp(query_parameters, scope="session"):
    dtmm_pivot = dt_misp_module_pivot(debug=True)
    response = dtmm_pivot.handler(json.dumps(query_parameters))
    return response


class TestPivot:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_pivot_resp):
        self.dtmm_pivot_resp = dtmm_pivot_resp

    def test_pivot_has_results(self):
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0

    def test_pivot_has_no_results_if_empty_query(self):
        dtmm_pivot = dt_misp_module_pivot()
        response = dtmm_pivot.handler()
        assert response == False

    def test_pivot_has_introspection(self, query_parameters):
        dtmm_pivot = dt_misp_module_pivot(json.dumps(query_parameters))
        assert dtmm_pivot.introspection() is not None

    def test_pivot_has_introspection_even_if_empty_query(self):
        dtmm_pivot = dt_misp_module_pivot()
        assert dtmm_pivot.introspection() is not None

    def test_pivot_has_version(self, version):
        dtmm_pivot = dt_misp_module_pivot()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                The module is superseded by the Iris Pivot module, but remains here for backward compatibility.
                Optimized for enrichment actions, the Pivot capability provides additional context on indicators by automatically building out a list of connected infrastructure from the counts presented in the Analyze capability.
                The Pivot module will also expand email addresses to a list of other domains that share the same contact information, and expand IP addresses to the list of other domains pointed to the same IP.
                Leverages the following DomainTools endpoints: Parsed Whois, Domain Profile, Risk, Reverse IP, Reverse Whois.
                """,
            "module-type": ["expansion"],
            "config": ["username", "api_key", "results_limit"],
        }

        assert expected_version == dtmm_pivot.version()

    def test_pivot_whois_registrant_email(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "whois-registrant-email" in record["values"]:
                the_test = True
        assert the_test is True

    def test_pivot_whois_registrant_phone(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "whois-registrant-phone" in record["values"]:
                the_test = True
        assert the_test is True

    def test_pivot_whois_registrant_name(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "whois-registrant-name" in record["values"]:
                the_test = True
        assert the_test is True

    def test_pivot_colocated_count(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "co-located domain count" in record["values"]:
                the_test = True
        assert the_test is True

    def test_pivot_risk_score(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "risk score" in record["values"]:
                the_test = True
        assert the_test is True

    def test_pivot_whois_registrant_name(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "whois-registrant-name" in record["values"]:
                the_test = True
        assert the_test is True

    def test_pivot_colocated_count(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "co-located domain count" in record["values"]:
                the_test = True
        assert the_test is True

    def test_pivot_risk_score(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "risk score" in record["values"]:
                the_test = True
        assert the_test is True

    def test_historic_whois_registrant_email(self):
        the_test = False
        assert "results" in self.dtmm_pivot_resp
        assert len(self.dtmm_pivot_resp["results"]) > 0
        for record in self.dtmm_pivot_resp["results"]:
            if "whois-registrant-email" in record["values"]:
                the_test = True
        assert the_test is True
