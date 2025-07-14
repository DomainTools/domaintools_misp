from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging
from domaintools_misp import base
from domaintools_misp._version import current as version

logger = logging.getLogger(__name__)


class dt_misp_module_iris_pivot(base.dt_misp_module_base):
    def __init__(self, debug=False):
        self.module_info = {
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
        }
        self.module = {"name": "DomainTools-Iris-Pivot"}

        base.dt_misp_module_base.__init__(self)
        self.module_config.append("guided_pivot_threshold")
        self.misp_attributes["input"] = [
            "domain",
            "ip-src",
            "ip-dst",
            "whois-registrant-email",
            "email-dst",
            "email-src",
            "hostname",
            "whois-registrar",
            "whois-registrant-name",
            "x509-fingerprint-sha1",
        ]

        if debug:
            self.log = logging.getLogger("DomainTools Iris Pivot")
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
