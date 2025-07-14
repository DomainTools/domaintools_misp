import json
import pytest

from domaintools_misp.iris_detect import dt_misp_module_iris_detect


@pytest.fixture
def dtmm_iris_detect_resp(query_parameters, scope="session"):
    query_parameters["config"].update(
        {
            "api_endpoint": "0",
            "test_mode": "1",
            "include_domain_data": "1",
            "risk_score_ranges": "0",
            "escalation_types": "0",
            "discovered_date": "None",
            "changed_since": "None",
            "escalated_since": "None",
        }
    )
    query_parameters["data"] = {"dummy": "data"}
    query_parameters.pop("domain")
    dtmm_iris_detect = dt_misp_module_iris_detect()
    response = dtmm_iris_detect.handler(json.dumps(query_parameters))
    return response


class TestIrisDetect:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_iris_detect_resp, logger):
        self.dtmm_iris_detect_resp = dtmm_iris_detect_resp
        self.logger = logger

    def test_iris_detect_has_no_results_if_empty_query(self):
        dtmm_iris_detect = dt_misp_module_iris_detect()
        response = dtmm_iris_detect.handler()
        assert response == False

    def test_iris_detect_has_introspection(self, query_parameters):
        dtmm_iris_detect = dt_misp_module_iris_detect(json.dumps(query_parameters))
        assert dtmm_iris_detect.introspection() is not None

    def test_iris_detect_has_introspection_even_if_empty_query(self):
        dtmm_iris_detect = dt_misp_module_iris_detect()
        assert dtmm_iris_detect.introspection() is not None

    def test_iris_detect_has_version(self, version):
        dtmm_iris_detect = dt_misp_module_iris_detect()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Imports newly discovered and/or newly changed domains from DomainTools Iris Detect product.
                Set up and manage monitored terms using the Iris Detect UI (https://iris.domaintools.com/detect/) then automatically import them into MISP using this module.
                Requires Iris Detect account provisioning
                """,
            "module-type": ["import"],
            "config": ["username", "api_key", "results_limit"],
        }

        assert expected_version == dtmm_iris_detect.version()

    def test_iris_detect_if_attributes_exist_in_results(self):
        assert "results" in self.dtmm_iris_detect_resp
        assert len(self.dtmm_iris_detect_resp["results"]) > 0

        is_attribute_exists = False
        for attribute_type in ["domain", "ip-src"]:
            for data in self.dtmm_iris_detect_resp["results"]:
                if attribute_type in data["type"]:
                    is_attribute_exists = True

            if not is_attribute_exists:
                self.logger.error(f"Attribute type {attribute_type} does not exist.")

            assert is_attribute_exists

            # Reset attribute assertion basis
            is_attribute_exists = False
