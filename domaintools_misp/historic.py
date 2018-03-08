from __future__ import absolute_import, unicode_literals, print_function, division
import sys
import logging
from domaintools_misp import base

logger = logging.getLogger(__name__)

class dt_misp_module_historic(base.dt_misp_module_base):
    def __init__(self, debug = False):
        self.module_info = {
            'version': '1.8.9',
            'author': 'DomainTools, LLC',
            'description': 'The DomainTools Historic module accesses historical Whois and hosting history to expand domain names to lists of registrars, IPs and emails historically connected with that domain.',
            'module-type': ['expansion']
        }
        self.module = {
            'type': ['expansion'],
            'name': 'DomainTools-Historic'
        }
        self.results_limit = 500
        base.dt_misp_module_base.__init__(self)

        if debug:
            self.log = logging.getLogger('DomainTools Historic')
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