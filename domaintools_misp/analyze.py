from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging

from domaintools_misp import base
from domaintools_misp._version import current as version

logger = logging.getLogger(__name__)


class dt_misp_module_analyze(base.dt_misp_module_base):
    def __init__(self, debug=False):
        self.module_info = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                This module is superseded by the Iris Investigate module but remains here for backward compatibility.
                Optimized for MISP hover actions, the Analyze capability provides Whois data, a Domain Risk Score and counts of connected domains to help give quick context on an indicator to inform an interesting pivot and map connected infrastructure.
                Leverages the following DomainTools endpoints: Parsed Whois, Domain Profile, Risk, Reverse IP, Reverse Whois.
                """,
            "module-type": ["hover"],
        }
        self.module = {"name": "DomainTools-Analyze"}
        base.dt_misp_module_base.__init__(self)

        if debug:
            self.log = logging.getLogger("DomainTools Analyze")
            self.log.setLevel(logging.DEBUG)
            self.ch = logging.StreamHandler(sys.stdout)
            self.ch.setLevel(logging.DEBUG)
            self.formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            self.ch.setFormatter(self.formatter)
            self.log.addHandler(self.ch)
            self.debug = True

    def handler(self, q=False):
        if not q:
            return q
        return self.process_request(q)

    def introspection(self):
        return self.misp_attributes

    def version(self):
        self.module_info["config"] = self.module_config
        return self.module_info
