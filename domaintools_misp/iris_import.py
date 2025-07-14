from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging
from domaintools_misp import base
from domaintools_misp._version import current as version

logger = logging.getLogger(__name__)


class dt_misp_module_iris_import(base.dt_misp_module_base):
    def __init__(self, debug=False):
        self.module_info = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                Import domains from the Iris Investigate Pivot Engine directly to a MISP event.
                Export an investigation from the Iris Investigate UI by copying the search hash (Menu -> Search -> Filters -> Export), importing a list of up to 5000 domains as indicators into MISP.
                Requires Iris Investigate account provisioning.
                """,
            "module-type": ["import"],
        }
        self.module = {"name": "DomainTools-Iris-Import"}
        self.results_limit = 500
        base.dt_misp_module_base.__init__(self)
        self.misp_attributes["input"] = ["data"]

        if debug:
            self.log = logging.getLogger("DomainTools Iris Import")
            self.log.setLevel(logging.DEBUG)
            self.ch = logging.StreamHandler(sys.stdout)
            self.ch.setLevel(logging.DEBUG)
            self.formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            self.ch.setFormatter(self.formatter)
            self.log.addHandler(self.ch)
            self.debug = True

    def introspection(self):
        return {"inputSource": ["paste"]}

    def version(self):
        self.module_info["config"] = self.module_config
        return self.module_info

    def handler(self, q=False):
        if not q:
            return q

        return self.process_request(q)
