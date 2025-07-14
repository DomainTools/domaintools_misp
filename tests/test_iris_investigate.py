import json
import pytest

from domaintools_misp.iris_investigate import dt_misp_module_iris_investigate


@pytest.fixture
def dtmm_iris_investigate_resp(query_parameters, scope="session"):
    dtmm_iris_investigate = dt_misp_module_iris_investigate()
    response = dtmm_iris_investigate.handler(json.dumps(query_parameters))
    return response


class TestIrisInvestigate:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_iris_investigate_resp, logger):
        self.dtmm_iris_investigate_resp = dtmm_iris_investigate_resp
        self.logger = logger

    def test_iris_investigate_has_no_results_if_empty_query(self):
        dtmm_iris_investigate = dt_misp_module_iris_investigate()
        response = dtmm_iris_investigate.handler()
        assert response == False

    def test_iris_investigate_has_introspection(self, query_parameters):
        dtmm_iris_investigate = dt_misp_module_iris_investigate(json.dumps(query_parameters))
        assert dtmm_iris_investigate.introspection() is not None

    def test_iris_investigate_has_introspection_even_if_empty_query(self):
        dtmm_iris_investigate = dt_misp_module_iris_investigate()
        assert dtmm_iris_investigate.introspection() is not None

    def test_iris_investigate_has_version(self, version):
        dtmm_iris_investigate = dt_misp_module_iris_investigate()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Designed for MISP tooltip or hover actions on domain names.
                Provides risk scoring, domain age, hosting, Whois, MX and related infrastructure for a domain.
                Guided Pivot counts help investigators identify connected attributes to other domain infrastructure.
                Requires Iris Investigate account provisioning.
                """,
            "module-type": ["expansion", "hover"],
            "config": ["username", "api_key", "results_limit"],
        }

        assert expected_version == dtmm_iris_investigate.version()

    def test_iris_investigate_if_attributes_exist_in_results(self):
        assert "results" in self.dtmm_iris_investigate_resp
        assert len(self.dtmm_iris_investigate_resp["results"]) > 0

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
            "IP Address",
            "IP Country Code",
            "IP ISP",
            "Name Server",
            "Mail Server Host",
            "Guided Pivot",
        ]:
            for data in self.dtmm_iris_investigate_resp["results"]:
                if attribute in data["values"]:
                    is_attribute_exists = True

            if not is_attribute_exists:
                self.logger.error(f"Attribute {attribute} does not exist.")

            assert is_attribute_exists

            # Reset attribute assertion basis
            is_attribute_exists = False

    def test_iris_investigate_type_host_should_be_changed_to_hostname_for_specific_attributes(self):
        assert "results" in self.dtmm_iris_investigate_resp
        assert len(self.dtmm_iris_investigate_resp["results"]) > 0

        for attribute in [
            "Name Server",
            "Name Server Host",
            "Name Server Domain",
            "Mx Host",
            "Email Domain",
        ]:
            for data in self.dtmm_iris_investigate_resp["results"]:
                if attribute in data["values"]:
                    assert data["types"] == ["hostname"]

                assert data["types"] != ["host"]
