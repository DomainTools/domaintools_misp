import logging
from domaintools_misp import base
from domaintools_misp._version import current as version

logger = logging.getLogger(__name__)


class dt_misp_module_iris_enrich(base.dt_misp_module_base):
    def __init__(self, debug=False):
        self.module_info = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Optimized for high-volume domain enrichment, providing Risk scoring, Hosting, Whois, MX and related infrastructure information for a domain.
                Requires Iris Enrich account provisioning.
                """,
            "module-type": ["expansion", "hover"],
        }
        self.module = {"name": "DomainTools-Iris-Enrich"}
        base.dt_misp_module_base.__init__(self)
        self.misp_attributes["input"] = ["domain"]

    def handler(self, q=False):
        if not q:
            return q

        return self.process_request(q)

    def introspection(self):
        return self.misp_attributes

    def version(self):
        self.module_info["config"] = self.module_config
        return self.module_info
