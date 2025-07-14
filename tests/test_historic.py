import json
import pytest

from domaintools_misp.historic import dt_misp_module_historic


@pytest.fixture
def dtmm_historic_resp(query_parameters, scope="session"):
    dtmm_historic = dt_misp_module_historic(debug=True)
    response = dtmm_historic.handler(json.dumps(query_parameters))
    return response


class TestHistoric:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_historic_resp):
        self.dtmm_historic_resp = dtmm_historic_resp

    def test_historic_has_results(self):
        assert "results" in self.dtmm_historic_resp
        assert len(self.dtmm_historic_resp["results"]) > 0

    def test_historic_has_no_results_if_empty_query(self):
        dtmm_historic = dt_misp_module_historic()
        response = dtmm_historic.handler()
        assert response == False

    def test_historic_has_introspection(self, query_parameters):
        dtmm_historic = dt_misp_module_historic(json.dumps(query_parameters))
        assert dtmm_historic.introspection() is not None

    def test_historic_has_introspection_even_if_empty_query(self):
        dtmm_historic = dt_misp_module_historic()
        assert dtmm_historic.introspection() is not None

    def test_historic_has_version(self, version):
        dtmm_historic = dt_misp_module_historic()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                The Historic capability will act on Domains or URLs to find historical context by expanding domain names to lists of registrars, IPs and emails historically connected with that indicator.
                Leverages the following DomainTools endpoints: Whois History, Hosting History, Domain Profile, Reverse IP, Reverse Whois, Parsed Whois, Whois.
                """,
            "module-type": ["expansion"],
            "config": ["username", "api_key", "results_limit"],
        }

        assert expected_version == dtmm_historic.version()

    def test_historic_hosting_history(self):
        the_test = False
        assert "results" in self.dtmm_historic_resp
        assert len(self.dtmm_historic_resp["results"]) > 0
        for record in self.dtmm_historic_resp["results"]:
            if "ip" in record["values"]:
                the_test = True
        assert the_test is True
