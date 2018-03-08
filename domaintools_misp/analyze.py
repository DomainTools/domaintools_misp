from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging
from domaintools_misp import base

logger = logging.getLogger(__name__)

class dt_misp_module_analyze(base.dt_misp_module_base):

    def __init__(self, debug = False):
        self.module_info = {
            'version': '1.8.9',
            'author': 'DomainTools, LLC',
            'description': 'The DomainTools Analyze module is Optimized for MISP hover-actions, but can also be used for expansions. It provides essential Whois data, a domain name reputation score, and counts of related domains.',
            'module-type': ['hover']
        }
        self.module = {
            'name': 'DomainTools-Analyze'
        }
        base.dt_misp_module_base.__init__(self)

        if debug:
            self.log = logging.getLogger('DomainTools Analyze')
            self.log.setLevel(logging.DEBUG)
            self.ch = logging.StreamHandler(sys.stdout)
            self.ch.setLevel(logging.DEBUG)
            self.formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
        self.module_info['config'] = self.module_config
        return self.module_info