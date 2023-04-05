import json
import pytest

from domaintools_misp.iris_investigate import dt_misp_module_iris_investigate


@pytest.fixture
def dtmm_iris_investigate_resp(query_parameters, scope="session"):
    dtmm_iris_investigate = dt_misp_module_iris_investigate()
    response = dtmm_iris_investigate.process_request(json.dumps(query_parameters))
    return response


class TestIrisInvestigate:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_iris_investigate_resp, logger):
        self.dtmm_iris_investigate_resp = dtmm_iris_investigate_resp
        self.logger = logger

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
            "Risk Score Component Threats",
            "Risk Score Component Evidence",
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
