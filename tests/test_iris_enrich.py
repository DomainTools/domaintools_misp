import json
import pytest

from domaintools_misp.iris_enrich import dt_misp_module_iris_enrich


@pytest.fixture
def dtmm_iris_enrich_resp(query_parameters, scope="session"):
    dtmm_iris_enrich = dt_misp_module_iris_enrich()
    response = dtmm_iris_enrich.handler(json.dumps(query_parameters))
    return response


class TestIrisEnrich:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_iris_enrich_resp, logger):
        self.dtmm_iris_enrich_resp = dtmm_iris_enrich_resp
        self.logger = logger

    def test_iris_enrich_has_no_results_if_empty_query(self):
        dtmm_iris_enrich = dt_misp_module_iris_enrich()
        response = dtmm_iris_enrich.handler()
        assert response == False

    def test_iris_enrich_has_introspection(self, query_parameters):
        dtmm_iris_enrich = dt_misp_module_iris_enrich(json.dumps(query_parameters))
        assert dtmm_iris_enrich.introspection() is not None

    def test_iris_enrich_has_introspection_even_if_empty_query(self):
        dtmm_iris_enrich = dt_misp_module_iris_enrich()
        assert dtmm_iris_enrich.introspection() is not None

    def test_iris_enrich_has_version(self, version):
        dtmm_iris_enrich = dt_misp_module_iris_enrich()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Optimized for high-volume domain enrichment, providing Risk scoring, Hosting, Whois, MX and related infrastructure information for a domain.
                Requires Iris Enrich account provisioning.
                """,
            "module-type": ["expansion", "hover"],
            "config": ["username", "api_key", "results_limit"],
        }

        assert expected_version == dtmm_iris_enrich.version()

    def test_iris_enrich_if_attributes_exist_in_results(self):
        assert "results" in self.dtmm_iris_enrich_resp
        assert len(self.dtmm_iris_enrich_resp["results"]) > 0

        is_attribute_exists = False
        for attribute in [
            "Create Date",
            "Domain Age",
            "Expiration Date",
            "Registrant Name",
            "Registrant Email",
            "Registrar Name",
            "Registrant Organization",
            "Risk Score",
            "Risk Score Component",
            "Active",
            "Technical Contact Name",
            "Technical Contact Street",
            "Technical Contact City",
            "Technical Contact State",
            "Technical Contact Postal",
            "Technical Contact Country",
            "Technical Contact Phone",
            "Technical Contact Email",
            "Admin Contact Name",
            "Admin Contact Street",
            "Admin Contact City",
            "Admin Contact State",
            "Admin Contact Postal",
            "Admin Contact Country",
            "Admin Contact Phone",
            "Admin Contact Email",
            "Registrar",
            "Registrant Contact Name",
            "Registrant Contact Street",
            "Registrant Contact City",
            "Registrant Contact State",
            "Registrant Contact Postal",
            "Registrant Contact Country",
            "Registrant Contact Phone",
            "Registrant Contact Email",
            "Ip Address",
            "Ip Asn",
            "Ip Country_Code",
            "Ip Isp",
            "Mx Host",
            "Mx Domain",
            "Mx Ip",
            "Email Domain",
            "Name Server Host",
            "Name Server Domain",
        ]:
            for data in self.dtmm_iris_enrich_resp["results"]:
                if attribute in data["values"]:
                    is_attribute_exists = True

            if not is_attribute_exists:
                self.logger.error(f"Attribute {attribute} does not exist.")

            assert is_attribute_exists

            # Reset attribute assertion basis
            is_attribute_exists = False

    def test_iris_enrich_type_host_should_be_changed_to_hostname_for_specific_attributes(self):
        assert "results" in self.dtmm_iris_enrich_resp
        assert len(self.dtmm_iris_enrich_resp["results"]) > 0

        for attribute in [
            "Name Server Host",
            "Name Server Domain",
            "Mx Host",
            "Mx Domain",
            "Email Domain",
        ]:
            for data in self.dtmm_iris_enrich_resp["results"]:
                if attribute in data["values"]:
                    assert data["types"] == ["hostname"]

                assert data["types"] != ["host"]
