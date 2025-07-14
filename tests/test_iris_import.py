import json
import pytest

from domaintools_misp.iris_import import dt_misp_module_iris_import


@pytest.fixture
def dtmm_iris_import_resp(query_parameters, scope="session"):
    query_parameters["data"] = (
        "VTJGc2RHVmtYMTliTmY0NlNaTW5WcHNOVzZ0SGU4ZE9wM1hqQ0hHMFVFRVBXY0dpYjk4R1NNZ2g0VVVWMzJFSGRQc0dDYVVyR3ZiUlBOMmNVMTMxb3N4dFBIcFMyZHZyTUo5MFBvTlpRMzRQL1Q1T05wOWQ4WTYwRHlNb05vM1dQUElFcDVPT056aHRQa1djU1AxeWpxaE15cllwMlJ5WGNwbEpUUWJJSE9FMzBlc2toZDVnYjJUUVdFRGhwWlBrWTNJUVN4NGlObmZHV2xObnI0K09KZ24zM0JJdk02SytQY1RiWTlrRUFlT0FwWHl2Vmo5QnNsc1FZUkhWQnVuM2VReVhheVJpdlhNZDNPYVhHZmptRkNFNHJGUEZZQ3M2dVBLSWw3NEdIcXh6anhTYXNXbVFQcXYvcFl3WnJXVmhYSjBnSlhvVmpsTkVaajRZclcyQ0RyRjRCSFRLOW56U2N3N2tQODE2TFRhZVNFd2JBSjg2UC9KZHo3eHFmRVRFeHpFa2lpcjcrblpJWVFlM0d0OTk2Y3J0VTYvS0x5NmpkSjNiaGdXOVV6SXRMLzNQdzVPaFhValp3U1dUSmEzbm1hVHBTbCtBak00V216TEpuYUMxcGkyZnFDWkpQRmJmeUVFUHM5OG1ud1dTQlBydnowOEtJNjVscjk1TTZTbzVnaCtqZmZnb3ErWk1pcHFoMUFnZjlwUlByTzlVRGZmd082WGYrZG43MmRFPQ=="
    )
    query_parameters["config"]["results_limit"] = 100
    dtmm_iris_import = dt_misp_module_iris_import(debug=True)
    response = dtmm_iris_import.handler(json.dumps(query_parameters))
    return response


class TestIrisImport:
    @pytest.fixture(autouse=True)
    def setup(self, dtmm_iris_import_resp, logger):
        self.dtmm_iris_import_resp = dtmm_iris_import_resp
        self.logger = logger

    def test_iris_import_has_no_results_if_empty_query(self):
        dtmm_iris_import = dt_misp_module_iris_import()
        response = dtmm_iris_import.handler()
        assert response == False

    def test_iris_import_has_introspection(self, query_parameters):
        dtmm_iris_import = dt_misp_module_iris_import(json.dumps(query_parameters))
        assert dtmm_iris_import.introspection() is not None

    def test_iris_import_has_introspection_even_if_empty_query(self):
        dtmm_iris_import = dt_misp_module_iris_import()
        assert dtmm_iris_import.introspection() is not None

    def test_iris_import_has_version(self, version):
        dtmm_iris_import = dt_misp_module_iris_import()
        expected_version = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Import domains from the Iris Investigate Pivot Engine directly to a MISP event.
                Export an investigation from the Iris Investigate UI by copying the search hash (Menu -> Search -> Filters -> Export), importing a list of up to 5000 domains as indicators into MISP.
                Requires Iris Investigate account provisioning.
                """,
            "module-type": ["import"],
            "config": ["username", "api_key", "results_limit"],
        }

        assert expected_version == dtmm_iris_import.version()

    def test_iris_import_if_attributes_exist_in_results(self):
        assert "results" in self.dtmm_iris_import_resp
        assert len(self.dtmm_iris_import_resp["results"]) > 0

        is_attribute_exists = False
        for attribute in ["Domain"]:
            for data in self.dtmm_iris_import_resp["results"]:
                if attribute in data["values"]:
                    is_attribute_exists = True

            if not is_attribute_exists:
                self.logger.error(f"Attribute {attribute} does not exist.")

            assert is_attribute_exists

            # Reset attribute assertion basis
            is_attribute_exists = False
