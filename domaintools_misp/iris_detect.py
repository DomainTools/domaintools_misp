from domaintools_misp import base
from domaintools_misp.config import IRIS_DETECT_USER_CONFIG
from domaintools_misp._version import current as version


class dt_misp_module_iris_detect(base.dt_misp_module_base):
    def __init__(self, debug=False):
        self.module_info = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Imports newly discovered and/or newly changed domains from DomainTools Iris Detect product.
                Set up and manage monitored terms using the Iris Detect UI (https://iris.domaintools.com/detect/) then automatically import them into MISP using this module.
                Requires Iris Detect account provisioning
                """,
            "module-type": ["import"],
        }
        self.module = {"name": "DomainTools-Iris-Detect"}
        base.dt_misp_module_base.__init__(self)
        self.misp_attributes["input"] = ["data"]

    def handler(self, q=False):
        if not q:
            return q

        return self.process_request(q)

    def introspection(self):
        return {
            "userConfig": IRIS_DETECT_USER_CONFIG,
            "inputSource": [],  # It has to be empty to remove the default `Paste Input``
        }

    def version(self):
        self.module_info["config"] = self.module_config
        return self.module_info
