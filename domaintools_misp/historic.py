from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging

from domaintools_misp import base
from domaintools_misp._version import current as version

logger = logging.getLogger(__name__)


class dt_misp_module_historic(base.dt_misp_module_base):
    def __init__(self, debug=False):
        self.module_info = {
            "version": version,
            "author": "DomainTools, LLC",
            "description": """
                The Historic capability will act on Domains or URLs to find historical context by expanding domain names to lists of registrars, IPs and emails historically connected with that indicator.
                Leverages the following DomainTools endpoints: Whois History, Hosting History, Domain Profile, Reverse IP, Reverse Whois, Parsed Whois, Whois.
                """,
            "module-type": ["expansion"],
        }
        self.module = {"type": ["expansion"], "name": "DomainTools-Historic"}
        self.results_limit = 500
        base.dt_misp_module_base.__init__(self)

        if debug:
            self.log = logging.getLogger("DomainTools Historic")
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
