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
    response = dtmm_iris_detect.process_request(json.dumps(query_parameters))
    return response


class TestIrisImport:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_iris_detect_resp):
        self.dtmm_iris_detect_resp = dtmm_iris_detect_resp

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
