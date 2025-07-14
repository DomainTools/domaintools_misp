import json
import pytest

from domaintools_misp.iris_pivot import dt_misp_module_iris_pivot


@pytest.fixture
def dtmm_iris_pivot_resp(query_parameters, scope="session"):
    dtmm_iris_pivot = dt_misp_module_iris_pivot(debug=True)
    response = dtmm_iris_pivot.handler(json.dumps(query_parameters))
    return response


class TestIrisPivot:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_iris_pivot_resp, logger):
        self.dtmm_iris_pivot_resp = dtmm_iris_pivot_resp
        self.logger = logger

    def test_iris_pivot_has_no_results_if_empty_query(self):
        dtmm_iris_pivot = dt_misp_module_iris_pivot()
        response = dtmm_iris_pivot.handler()
        assert response == False

    def test_iris_pivot_has_introspection(self, query_parameters):
        dtmm_iris_pivot = dt_misp_module_iris_pivot(json.dumps(query_parameters))
        assert dtmm_iris_pivot.introspection() is not None

    def test_iris_pivot_has_introspection_even_if_empty_query(self):
        dtmm_iris_pivot = dt_misp_module_iris_pivot()
        assert dtmm_iris_pivot.introspection() is not None

    def test_iris_pivot_has_version(self, version):
        dtmm_iris_pivot = dt_misp_module_iris_pivot()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Enriches domain attributes with nearly every available field from the Iris Investigate API.
                Includes complete Risk Score data, with component scores and evidence when available.
                Adds Guided Pivot counts to attribute comments.
                Tags attributes as potential Guided Pivots when connections are shared with fewer than 300 domains (this can be configured in the module attributes).
                Enables pivots on IPs, SSL hashes, nameserver hostnames, and registrant email addresses.
                Requires Iris Investigate account provisioning.
                """,
            "module-type": ["expansion"],
            "config": [
                "username",
                "api_key",
                "results_limit",
                "guided_pivot_threshold",
            ],
        }

        assert expected_version == dtmm_iris_pivot.version()

    def test_iris_pivot_check_if_attributes_exist_in_results(self):
        assert "results" in self.dtmm_iris_pivot_resp
        assert len(self.dtmm_iris_pivot_resp["results"]) > 0

        is_attribute_exists = False
        for attribute in [
            "Website Response",
            "Create Date",
            "Expiration Date",
            "Registrar",
            "Technical Contact Name",
            "Technical Contact Street",
            "Technical Contact State",
            "Technical Contact City",
            "Technical Contact Country",
            "Technical Contact Postal",
            "Technical Contact Phone",
            "Technical Contact Email",
            "Registrant Contact Name",
            "Registrant Contact Street",
            "Registrant Contact State",
            "Registrant Contact City",
            "Registrant Contact Country",
            "Registrant Contact Postal",
            "Registrant Contact Phone",
            "Registrant Contact Email",
            "Admin Contact Name",
            "Admin Contact Street",
            "Admin Contact State",
            "Admin Contact City",
            "Admin Contact Country",
            "Admin Contact Postal",
            "Admin Contact Phone",
            "Admin Contact Email",
            "IP Address",
            "Country Code",
            "IP ISP",
            "IP ASN",
            "Name Server Host",
            "Name Server Domain",
            "Name Server IP",
            "Mail Server Host",
            "Mail Server Domain",
            "Mail Server IP",
            "SOA email",
            "Whois Email",
            "Risk Score",
            "proximity Risk Component",
        ]:
            for data in self.dtmm_iris_pivot_resp["results"]:
                if attribute in data["values"]:
                    is_attribute_exists = True

            if not is_attribute_exists:
                self.logger.error(f"Attribute {attribute} does not exist.")

            assert is_attribute_exists

            # Reset attribute assertion basis
            is_attribute_exists = False
