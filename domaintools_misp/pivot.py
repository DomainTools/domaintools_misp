from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging
from domaintools_misp import base

logger = logging.getLogger(__name__)

class dt_misp_module_pivot(base.dt_misp_module_base):
    def __init__(self, debug = False):
        self.module_info = {
            'version': '1.8.9',
            'author': 'DomainTools, LLC',
            'description': 'The DomainTools Pivot module expands domains and hostnames to include a complete set of Whois attributes, plus reputation scores and counts of related domains. The Pivot module will also expand email addresses to a list of other domains that share the same contact information, and expand IP addresses to the list of other domains pointed to the same IP.',
            'module-type': ['expansion']
        }
        self.module = {
            'name': 'DomainTools-Pivot'
        }
        self.results_limit = 1000
        base.dt_misp_module_base.__init__(self)

        if debug:
            self.log = logging.getLogger('DomainTools Pivot')
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

