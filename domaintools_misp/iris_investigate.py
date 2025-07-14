from domaintools_misp import base
from domaintools_misp._version import current as version


class dt_misp_module_iris_investigate(base.dt_misp_module_base):
    def __init__(self, debug=False):
        self.module_info = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Designed for MISP tooltip or hover actions on domain names.
                Provides risk scoring, domain age, hosting, Whois, MX and related infrastructure for a domain.
                Guided Pivot counts help investigators identify connected attributes to other domain infrastructure.
                Requires Iris Investigate account provisioning.
                """,
            "module-type": ["expansion", "hover"],
        }
        self.module = {"name": "DomainTools-Iris-Investigate"}
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
